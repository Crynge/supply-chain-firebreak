from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]
SCREENSHOT_DIR = ROOT / "docs" / "screenshots"
APP_URL = "http://127.0.0.1:5192"


def main() -> None:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1500, "height": 2200}, color_scheme="dark")
        page.goto(APP_URL, wait_until="networkidle")
        page.screenshot(path=str(SCREENSHOT_DIR / "dashboard.png"), full_page=True)

        page.get_by_role("button", name="critical").click()
        page.wait_for_timeout(300)
        page.screenshot(path=str(SCREENSHOT_DIR / "findings.png"), full_page=True)
        browser.close()


if __name__ == "__main__":
    main()
