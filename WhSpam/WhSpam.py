from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time


driver = webdriver.Chrome()
driver.get("https://web.whatsapp.com/")

input("امسح رمز QR ثم اضغط Enter هنا...")


target_name = "Yusef Egypt"       #حدد اسم الشخص أو المجموعة
message = "انا عمك يا ورعع "
count = 50                            # عدد الرسائل


user = driver.find_element(By.XPATH, f'//span[@title="{target_name}"]')
user.click()


msg_box = driver.find_element(By.XPATH, '//div[@contenteditable="true"][@data-tab="10"]')

for i in range(count):
    msg_box.send_keys(message)
    msg_box.send_keys(Keys.ENTER)
    time.sleep(1)                     # تأخير طفيف لتجنب الحظر الفوري للنظام