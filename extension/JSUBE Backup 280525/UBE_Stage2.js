import {fetchJson} from './fetchJson.js';
import {getDomain} from 'tldts';
import {DateTime} from 'luxon';
import net from 'net';
import {parse as pslParseDomain} from 'psl';
import https from "node:https";

const RESPONSE_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
};
const TIMEOUT_WHOIS = 3000;
const TIMEOUT_REDIRECTS = 3000;
const HEADERS = [
    'Final Domain',
    'Has SSL',
    'Valid SSL',
    'Issuer',
    'Age',
    'Expiry',
    'Registrar',
    'Reputation',
    'VT Malicious',
    'VT Suspicious',
    'VT Harmless',
    'VT Undetected',
    'Different Domains'
]

export function followRedirects(parsedOriginalURL) {
    if (parsedOriginalURL.protocol !== 'https:') {
        return Promise.resolve(getDomain(parsedOriginalURL));
    }

    return new Promise((resolve) => {
        try {
            const maxRedirects = 10;
            const timeoutDuration = TIMEOUT_REDIRECTS;

            const timeout = setTimeout(() => {
                console.error(`Timeout after ${timeoutDuration} ms`);
                resolve(getDomain(parsedOriginalURL.hostname));
            }, timeoutDuration);

            let redirectCount = 0;

            const follow = (url) => {
                const parsed = new URL(url);
                const options = {
                    method: 'HEAD',
                    hostname: parsed.hostname,
                    path: parsed.pathname + parsed.search,
                };

                const req = https.request(options, (res) => {
                    const {statusCode, headers} = res;
                    const location = headers.location;

                    res.resume();

                    if ([301, 302, 303, 307, 308].includes(statusCode) && location) {
                        if (++redirectCount > maxRedirects) {
                            clearTimeout(timeout);
                            console.error('Too many redirects');

                            return resolve(getDomain(parsedOriginalURL.hostname));
                        }

                        const nextURL = new URL(location, parsed).href;

                        return follow(nextURL);
                    } else {
                        clearTimeout(timeout);

                        return resolve(getDomain(url));
                    }
                });

                req.on('error', (err) => {
                    clearTimeout(timeout);
                    console.error('Request error: ', err);
                    resolve(getDomain(parsedOriginalURL.hostname));
                });

                req.end();
            };

            follow(parsedOriginalURL.href);
        } catch (error) {
            console.error('Unexpected error: ', error);
            resolve(getDomain(parsedOriginalURL.hostname));
        }
    });
}

function getPublicSuffix(domain) {
    const parsed = pslParseDomain(domain);

    if (!parsed || !parsed.tld) {
        console.error("Failed to get TLD for domain");

        return null;
    }

    return parsed.tld;
}

function extractServer(serverResponse, tld) {
    const match = serverResponse.match(/^whois:\s*(\S+)$/im);

    if (match && match[1]) {
        return match[1].trim();
    }

    console.error(`WHOIS server not found in IANA response for TLD: ${tld}`);

    return null;
}

function queryWhoisServer(server, query) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(43, server, () => {
            socket.write(query + '\r\n');
        });

        let data = '';
        let timeout = setTimeout(() => {
            socket.destroy();
            reject(new Error(`Timeout: ${server} did not respond in ${TIMEOUT_WHOIS} ms`));
        }, TIMEOUT_WHOIS);

        socket.setEncoding('utf8');
        socket.on('data', chunk => data += chunk);
        socket.on('end', () => {
            clearTimeout(timeout);
            resolve(data);
        });
        socket.on('error', err => {
            clearTimeout(timeout);
            reject(err);
        });
    });
}

async function getWhoisFromIana(domain) {
    const tld = getPublicSuffix(domain);
    let defaultResponse = {
        'Age': -1,
        'Expiry': -1,
        'Registrar': "Unknown"
    };

    if (tld) {
        try {
            const serverResponse = await queryWhoisServer('whois.iana.org', tld);
            const server = extractServer(serverResponse, tld);

            if (server) {
                const rawWhois = await queryWhoisServer(server, domain);

                return parseWhoisResponse(rawWhois);
            }
        } catch (error) {
            console.error(error);
        }
    }

    return defaultResponse;
}

function findMatchFromKeys(rawWhois, keys) {
    const pattern = new RegExp(`(${keys.join("|")}):\\s*(.+)`, "i");
    const match = pattern.exec(rawWhois);

    return match ? match[2].trim() : null;
}

function calculateDaysFromDate(dateStr, direction) {
    let parsedDT = DateTime.fromISO(dateStr);

    if (!parsedDT.isValid) {
        const formats = [
            "yyyy-MM-dd",
            "yyyy/MM/dd",
            "yyyy MM dd",

            "dd-MM-yyyy",
            "dd/MM/yyyy",
            "dd MM yyyy",

            "MM-dd-yyyy",
            "MM/dd/yyyy",
            "MM dd yyyy",

            "yyyy-MM-dd HH:mm",
            "dd-MM-yyyy HH:mm",
            "MM/dd/yyyy hh:mm a",

            "yyyy-MM-dd'T'HH:mm:ssZZ",
            "yyyy-MM-dd HH:mm:ss ZZZ",
            "dd-MM-yyyy HH:mm:ss ZZZ",

            "d MMM yyyy",
            "d MMMM yyyy",
            "MMM d, yyyy",
        ];

        for (const fmt of formats) {
            parsedDT = DateTime.fromFormat(dateStr, fmt, {zone: "utc"});

            if (parsedDT.isValid) {
                break;
            }
        }
    }

    if (!parsedDT.isValid) {
        console.error('Failed to calculate days from date: Invalid dateParsedStr');

        return null;
    }


    const now = DateTime.utc();
    const diff = (parsedDT.toUTC().diff(now, 'days').days).toFixed(1);

    return direction === 'past' ? -diff : diff;
}

function getDomainAge(rawWhois) {
    const creationKeys = [
        "Registered", "Registered On", "Domain Registration Date", "registration date",
        "Registration Time", "created", "Created On", "Create date", "Creation Date"
    ];
    const creationDateMatch = findMatchFromKeys(rawWhois, creationKeys);

    if (creationDateMatch) {
        const age = calculateDaysFromDate(creationDateMatch, "past");

        return age ? age : -1;
    }

    console.error('Failed to get domain age: No pattern match')

    return -1
}

function getDomainExpiry(rawWhois) {
    const expiryKeys = ["Registry Expiry Date", "Registry Expiration Date", "Expiry Date", "renewal date",
        "Expiration Date", "expires", "expire", "paid-till", "paid till", "Expiration Time",
        "Domain expires"]
    const expiryDateMatch = findMatchFromKeys(rawWhois, expiryKeys);

    if (expiryDateMatch) {
        const expiryInDays = calculateDaysFromDate(expiryDateMatch, "future");

        return expiryInDays ? expiryInDays : -1;
    }

    console.error('Failed to get domain expiry date: No pattern match')

    return -1;
}

function getDomainRegistrar(rawWhois) {
    const registrarKeys = ["Registrar", "Registrar Name", "Domain registrar url",
        "Domain registrant url", "Domain registrant",
        "Authorised Registrar", "Domain registrar",
        "Registrant", "Sponsoring Registrar"]

    const registrarMatch = findMatchFromKeys(rawWhois, registrarKeys);

    if (!registrarMatch) {
        console.error('Failed to get domain registrar: No pattern match')

        return "Unknown";
    }

    return registrarMatch;
}

function parseWhoisResponse(rawWhois) {
    const age = getDomainAge(rawWhois);
    const expiry = getDomainExpiry(rawWhois);
    const registrar = getDomainRegistrar(rawWhois);

    return {
        'Age': age,
        'Expiry': expiry,
        'Registrar': registrar
    }
}

function extractSSLDetails(certificate) {
    if (!certificate) {
        console.error('Failed to extract SSL details: No certificate');
        return {'Has SSL': 0, 'Valid SSL': 0, 'Issuer': "Unknown"};
    }

    const issuer = certificate.issuer?.O || "Unknown"
    const validFrom = certificate.validity?.not_before;
    const validTo = certificate.validity?.not_after;
    const dateValidFrom = new Date(validFrom);
    const dateValidTo = new Date(validTo);

    if (isNaN(dateValidFrom) || isNaN(dateValidTo)) {
        console.error('Failed to extract SSL details: Parsed invalid dates')
    }

    let validExpiryDate = dateValidTo - dateValidFrom > 0 ? 1 : 0;

    return {'Has SSL': 1, 'Valid SSL': validExpiryDate, 'Issuer': issuer};
}

function validateBodyAndURL(body) {
    if (!body) {
        throw new Error("Invalid event body")
    }

    if (Object.keys(body).length === 0) {
        throw new Error("Empty body");
    }

    if (!body.url || typeof body.url !== 'string') {
        throw new Error("Missing or invalid 'url' field");
    }

    let parsedFullURL;

    try {
        parsedFullURL = new URL(body.url);
    } catch (error) {
        throw new Error("Failed to parse URL: " + error.message);
    }

    return parsedFullURL;
}

async function getResults(parsedFullURL, finalDomain, data) {
    const differentDomains = getDomain(parsedFullURL.hostname) !== finalDomain ? 1 : 0;
    const attributes = data?.data?.attributes || {};
    const reputation = attributes.reputation ?? null;
    const lastAnalysisStats = attributes.last_analysis_stats ?? null;
    const certificate = attributes.last_https_certificate ?? null;
    let whois = attributes.whois ?? null;

    if (reputation == null) {
        console.error(`Reputation score not found for domain ${finalDomain}`);
        throw new Error('Missing reputation score');
    }

    if (lastAnalysisStats == null) {
        console.error(`Last analysis stats not found for domain ${finalDomain}`);
        throw new Error('Missing last analysis stats');
    }

    if (whois == null) {
        console.warn(`WHOIS info not found for ${finalDomain}, retrying fallback`);
        whois = await getWhoisFromIana(finalDomain);
    } else {
        whois = parseWhoisResponse(whois);
    }

    const certificateDetails = extractSSLDetails(certificate);

    console.log(`Successfully extracted results for ${finalDomain}`);

    return constructResultsDict(parsedFullURL, finalDomain, certificateDetails, whois, reputation, lastAnalysisStats, differentDomains);
}

function constructResultsDict(parsedFullURL, finalDomain, certificateDetails, whois, reputation, lastAnalysisStats, differentDomains) {
    const parseResults = [
        finalDomain,
        certificateDetails['Has SSL'],
        certificateDetails['Valid SSL'],
        certificateDetails['Issuer'],
        whois['Age'],
        whois['Expiry'],
        whois['Registrar'],
        Number(reputation),
        lastAnalysisStats['malicious'],
        lastAnalysisStats['suspicious'],
        lastAnalysisStats['harmless'],
        lastAnalysisStats['undetected'],
        differentDomains
    ]

    return Object.fromEntries(HEADERS.map((key, i) => [key, parseResults[i]]));
}

export const handler = async (event) => {
    try {
        const body = JSON.parse(event.body || '{}');
        const parsedFullURL = validateBodyAndURL(body);
        const finalDomain = await followRedirects(parsedFullURL);
        const data = await fetchJson(finalDomain);

        console.log(`Fetched VT API results for ${finalDomain}`);

        const finalResults = await getResults(parsedFullURL, finalDomain, data);

        return {
            statusCode: 200,
            headers: RESPONSE_HEADERS,
            body: JSON.stringify(finalResults)
        };
    } catch (err) {
        console.error(err);

        return {
            statusCode: 500,
            headers: RESPONSE_HEADERS,
            body: JSON.stringify({error: 'Internal error: Failed to send a response', details: err.message}),
        };
    }
};