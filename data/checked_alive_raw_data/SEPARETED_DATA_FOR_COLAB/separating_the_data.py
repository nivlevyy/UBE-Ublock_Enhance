import pandas as pd
import math
import os
import  requests
url="https://google.com"
html = requests.get(url, timeout=3).text
print(html)

# def get_project_root():
#     return os.path.abspath(
#         os.path.join(os.path.dirname(__file__),"..","..", "..")
#     )
# PROJECT_ROOT = get_project_root()
# input_root=os.path.join(PROJECT_ROOT,"data","checked_alive_raw_data","safe_urls.csv")
# output_root=os.path.join(PROJECT_ROOT,"data","checked_alive_raw_data","SEPARETED_DATA_FOR_COLAB","LEGIT")
#
#
# df = pd.read_csv(input_root, sep=",", quotechar='"')
#
# chunk_size = 2600
#
# num_files = math.ceil(len(df) / chunk_size)
#
# for i in range(num_files):
#     start_row = i * chunk_size
#     end_row = start_row + chunk_size
#     chunk = df.iloc[start_row:end_row]
#     chunk.to_csv(f'{output_root}/safe_urls_part_{i+1}.csv', index=False,header=True)
#
