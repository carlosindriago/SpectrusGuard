import os
from playwright.sync_api import sync_playwright, expect

def run_test():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Load local HTML file
        file_path = os.path.abspath("verification/verify_toast.html")
        page.goto(f"file://{file_path}")

        # Click Success Button
        page.get_by_role("button", name="Show Success").click()

        # Verify Toast appears
        toast = page.locator(".sg-toast.success")
        expect(toast).to_be_visible()
        expect(toast).to_have_attribute("role", "status")
        expect(toast.locator(".sg-toast-icon")).to_contain_text("✅")

        # Click Error Button
        page.get_by_role("button", name="Show Error").click()

        # Verify Error Toast appears
        error_toast = page.locator(".sg-toast.error")
        expect(error_toast).to_be_visible()
        expect(error_toast).to_have_attribute("role", "alert")
        expect(error_toast.locator(".sg-toast-icon")).to_contain_text("🚨")

        # Take Screenshot
        page.screenshot(path="verification/toast_verification.png")
        print("Verification successful!")

        browser.close()

if __name__ == "__main__":
    run_test()
