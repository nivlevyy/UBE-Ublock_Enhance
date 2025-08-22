
from urllib.parse import urlparse
urls = [
    # # בסיסיים
    # "https://www.phish1.evil/shitface",
    # "http://www.phish2.evil/",
    # "http://www.phish3.evil",
    #
    # # סאב-דומיין + path
    # "https://login.secure-paypal.evil/login",
    # "https://sub.sub2.evil.co/reset/index.html",
    #
    # # בלי סכמה (תתווסף אוטומטית ב-urlparse)
    # "phish4.evil",
    # "phish5.evil/",
    # "phish6.evil/login",
    #
    # # קבצים ותבניות נתיבים
    # "https://phish7.evil/a/b/c",
    # "https://phish8.evil/a/b/c/",
    # "https://phish9.evil/login.php",
    # "https://phish10.evil/path/to/index.html",
    #
    # # שאילתות/פרגמנטים (אמורים להתעלם ולייצר כלל לפי path בלבד)
    # "https://phish11.evil/login?u=1&t=2",
    # "https://phish12.evil/path/?a=1#frag",
    # "http://phish13.evil/?only=query",

    # # פורטים (נזרקים ע״י hostname)
    # "http://phish14.evil:8080/",
    # "https://phish15.evil:8443/login",
    #
    # # כתובות עם משתמש/סיסמה (hostname נשאר נקי)
    # "https://user:pass@phish16.evil/secret",
    # "http://user@phish17.evil/",
    #
    # # IPs
    # "http://127.0.0.1/",
    # "https://127.0.0.1/login",
    # "http://192.0.2.123:8080/panel",

    # IPv6 (עם סוגריים ב-URL; hostname נקי)
    "http://[2001:db8::1]/",
    "https://[2001:db8::2]/admin",
    #
    # # קישורי קיצור (שמים כלל לפי נתיב כדי לא לחסום דומיין שלם של קיצור)
    # "https://bit.ly/fake",
    # "https://t.co/AbCdEfG",
    # "http://tinyurl.com/xyz123",
    #
    # # “פלטפורמות גדולות” — פה בכל מקרה תופעל הלוגיקה שלך: אם יש path → נתיב; אם לא → דומיין
    # "https://sites.google.com/view/evil-campaign",
    # "https://github.io/health-records-x-ray",
    # "https://subdomain.github.io/repo/page.html",
    # "https://pages.dev/somepath/login",
    # "https://appspot.com/",
    # "https://storage.googleapis.com/bucket/evil/file",
    # "https://s3.amazonaws.com/bucket/key",
    # "https://blogspot.com/evil-post",
    #
    # # עם WWW (יורד)
    # "https://www.evil1.com",
    # "https://www.evil2.com/",
    # "https://www.evil3.com/login",
    # "http://www.evil4.co.uk/reset",
    #
    # # בלי WWW
    # "https://evil5.com",
    # "https://evil6.com/",
    # "https://evil7.com/login",
    #
    # # אותיות גדולות/מעורבות (יורד ל-lower)
    # "HTTPS://WWW.EvIl8.CoM/LoGiN",
    # "http://EVIL9.com",
    #
    # # סלאשים מרובים
    # "https://evil10.com////multi//slashes",
    # "http://evil11.com/path//to///phish",
    #
    # # דומיין מורכב (דמוי טייפו/הנדסה חברתית)
    # "https://paypal.com.login.secure.evil.com",
    # "https://microsoft.com.account.verify.evil.net/login",
    #
    # # Punycode (IDN)
    # "https://xn--paypl-6ve.com/login",  # דוגמה לטייפו כ־IDN
    # "http://xn--exmple-cua.com/",
    #
    # # FTP (עדיין יחולץ hostname; רק דוגמה קיצונית)
    # "ftp://ftp.evil.com/",
    # "ftp://ftp.evil.com/downloads/steal",
    #
    # # נתיב שורש בלבד
    # "https://rootpath.evil/",
    # "http://rootpath2.evil/",
    #
    # # דומיין בלי כלום
    # "https://justdomain.evil",
    # "http://justdomain2.evil",
    #
    # # path קצר מול ארוך
    # "https://shortpath.evil/a",
    # "https://longpath.evil/this/is/a/very/long/path/to/fake/login/index.php",
    #
    # # עם נקודה בסוף הדומיין (אם יש לך מקרים כאלה)
    # "http://traildot.evil./login",  # שים לב: urlparse.hostname מחזיר בלי הנקודה האחרונה ברוב המקרים
]
def main():

    # urls=["https://www.phish1.evil/shitface", "http://www.phish2.evil/","http://www.phish3.evil"]
    parsed_urls = set()
    text_file=""
    for u in urls:
         parsed = urlparse(u if '://' in u else 'http://' + u)
         if "www." in parsed.hostname:
            host=parsed.hostname.split("www.")[1].lower()
         else:
             host=parsed.hostname
         # print(parsed.path)
         host_for_rule = f'[{host}]' if ':' in host else host

         path = parsed.path or ''
         if path and path != '/':
             rule = f'||{host_for_rule}{path}$document,frame'
         else:
             rule = f'||{host_for_rule}^$all'
         parsed_urls.add(rule)
         text_file = "\n".join(sorted(parsed_urls))+"\n"
         print(rule)
    print('---------------boyaaaa----------')
    print(f'\n{text_file}')
    print("\n---------original-----------------------sorted")
    print(f'\n{sorted(urls)}')






    # new1=[row.replace("https://","") if "https://" in row else row.replace("http://","") for row in urls ]
    # print(new1)
    # # new2=[row.replace("https://","")  for row in urls ]
    # # print(new2)
    #
    #
    #
    # all_urls = ["||" + row + "^$all" for row in new1]
    # all_urls.sort()
    # text_file = "\n".join(all_urls)
    # print(text_file)



if __name__ == "__main__":
    main()