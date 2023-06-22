import mysql.connector
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from configparser import ConfigParser

# author: anuroopa palla
# date: 13 April,2023

# Method to get page content
def get_page(value=None):
    if(value=='first_page'):
        page_url = config.get('URL', 'cve_url')
    else:
        page_url = base_url+page.get('href')
    driver.get(page_url)
    page_content = driver.page_source
    return page_content

# Method to read config file settings
def read_config():
    config = ConfigParser()
    config.read('scraper_config.ini')
    return config

# Methods for Database connection
def create_connection():
    user = config.get('DATABASE', 'user')
    password = config.get('DATABASE', 'password')
    host = config.get('DATABASE', 'host')
    database = config.get('DATABASE', 'database')
    cnx = mysql.connector.connect(user=user, password=password, host=host, database=database)
    cursor = cnx.cursor()
    return cnx,cursor

def close_connection():
    cursor.close()
    cnx.close()

# Insert query method
def insert_query(cve_id, cwe_id, num_of_exploits, vulneribility_types, published_date, updated_date, score, gained_access_level, access, complexity, authentication, config, integration, availability):
    if (cell_dict):
        insert_query = "INSERT INTO cve_data (cve_id, cwe_id, num_of_exploits, vulneribility_types,published_date,updated_date,score,gained_access_level,access,complexity,authentication,config,integration,availability) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        cursor.execute(insert_query, (cve_id, cwe_id, num_of_exploits, vulneribility_types, published_date, updated_date,
                       score, gained_access_level, access, complexity, authentication, config, integration, availability))
        cnx.commit()
    return True

# Methods for Webdrivers 
def open_webdriver():
    chrome_driver_path = config.get('DRIVER_PATHS', 'chrome_driver')
    service = Service(executable_path=chrome_driver_path)
    web_driver = webdriver.Chrome(service=service)
    return web_driver

def close_webdriver():
    driver.quit()

config = read_config()
cnx,cursor=create_connection()
driver=open_webdriver()
base_page_content=get_page(value='first_page')
soup = BeautifulSoup(base_page_content, 'html.parser')

# table = soup.find('table', {'id': 'vulnslisttable'})
pages = soup.find('div', {'id': 'pagingb'})

# Iterate over the pages to get the data
for page in pages.findAll('a'):
    base_url = config.get('URL', 'base_url')
    next_page_content = get_page()
    soup1 = BeautifulSoup(next_page_content, 'html.parser')

    # Get the Security Vulnerabilities table element from each page
    page_table = soup1.find('table', {'id': 'vulnslisttable'})
    for row in page_table.find_all('tr'):
        cells = row.find_all('td')

        # Extract the rows with additional discription
        cvesummarylong_cells = row.find_all('td', {'class': 'cvesummarylong'})
        if len(cells) > 0:
            cell_dict = {}
            for index, cell in enumerate(cells):

                # To get only the rows with data and not the description
                if cell not in cvesummarylong_cells:

                    # Place the data inside the dictionary
                    cell_dict[index] = cell.text.strip()

                    # Insert to database part
                    flag=insert_query(cell_dict[1], cell_dict[2], cell_dict[3], cell_dict[4], cell_dict[5], cell_dict[6], cell_dict[7],
                                 cell_dict[8], cell_dict[9], cell_dict[10], cell_dict[11], cell_dict[12], cell_dict[13], cell_dict[14])
                    if(flag):
                        print("insert successful")
                    else:
                        print("some issue with data insertion")

            # below only for debug
            #print(cell_dict)

# Close the database connection and the webdriver
close_connection()
close_webdriver()