from datetime import datetime
from playwright.sync_api import sync_playwright

USERNAME = "x___.iix"  # استبدل هذا باسم حسابك

# الحصول على التاريخ والوقت لتسمية الملف
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context()
    page = context.new_page()

    print("جاري فتح الموقع... سجل دخولك في النافذة المفتوحة.")
    page.goto("https://www.instagram.com/")

    # الانتظار حتى تسجيل الدخول ورؤية الصفحة الرئيسية
    page.wait_for_selector("svg[aria-label='Home']", timeout=0)

    cookies = context.cookies()

    # رأس الملف يحتوي على اسم الحساب وتاريخ الاستخراج
    readable_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_content = f"=== Cookies for {USERNAME} ===\nDate: {readable_date}\n\n"

    target_keys = ["sessionid", "ds_user_id", "csrftoken", "rur"]

    for cookie in cookies:
        if cookie["name"] in target_keys:
            file_content += f"{cookie['name']}={cookie['value']}\n"

    # اسم الملف باسم الحساب والتاريخ (مثال: myaccount_2026-09-04_18-00-00.txt)
    file_name = f"{USERNAME}_{timestamp}.txt"

    with open(file_name, "w", encoding="utf-8") as file:
        file.write(file_content)

    print(f"\nتم حفظ الملف بنجاح باسم: {file_name}")
    browser.close()