"""
Instagram Group Chat Renamer

Usage examples:
python instagram_gc_renamer.py --username your_username --password your_password --thread-url https://www.instagram.com/direct/t/123/ --names "Spyther GC ✨,Spyther Power 💣,Spyther ⚡,Spyther Ultra 🌟" --headless false

Install instructions:
pip install playwright
playwright install
"""
import argparse
import json
import os
import time
import random
import logging
import re
import asyncio
from playwright.async_api import async_playwright, TimeoutError

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('instagram_gc_renamer.log'),
        logging.StreamHandler()
    ]
)

# Add this near the top, names_list ke just upar ya global me
INVISIBLE_CHARS = ["\u200B", "\u200C", "\u200D", "\u2060"]  # ZWS, ZWNJ, ZWJ, Word Joiner

async def apply_anti_detection(page):
    await page.evaluate("""() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        window.chrome = { app: {}, runtime: {} };
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
            Promise.resolve({ state: 'denied' }) :
            originalQuery(parameters)
        );
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            if (parameter === 37445) return 'Google Inc. (Intel)';
            if (parameter === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)';
            return getParameter.call(this, parameter);
        };
    }""")

async def prepare_new_tab(context, pending_page_ref, args):
    try:
        logging.info("🌀 Opening new tab in background...")
        new_page = await context.new_page()
        await apply_anti_detection(new_page)
        await new_page.goto(args.thread_url, timeout=60000)
        await setup_details_pane(new_page)
        await new_page.locator("div[role='button'][aria-label='Change group name']").wait_for(timeout=60000)
        pending_page_ref[0] = new_page
        logging.info("✅ New tab ready, waiting for switch after next save")
    except Exception as e:
        logging.error(f"❌ Error preparing new tab: {e}")
        if new_page:
            await new_page.close()

async def main():
    parser = argparse.ArgumentParser(description="Instagram Group Chat Renamer")
    parser.add_argument('--username', required=True, help='Instagram username')
    parser.add_argument('--password', required=False, default=None, help='Instagram password')
    parser.add_argument('--thread-url', required=True, help='Target thread URL')
    parser.add_argument('--names', default='', help='Comma or newline-separated list of names')
    parser.add_argument('--headless', default='true', help='Run in headless mode (true/false)')
    parser.add_argument('--storage-state', default=None, help='Path to storage state JSON')
    args = parser.parse_args()

    headless = args.headless.lower() == 'true'
    if args.storage_state:
        state_file = args.storage_state
    else:
        state_file = f"{args.username}_state.json"

    if args.names:
        names_list = [n.strip() for n in re.split(r'[,\n]', args.names) if n.strip()]
    else:
        names_list = []

    if not names_list:
        logging.error("No names provided.")
        return

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        if os.path.exists(state_file):
            logging.debug(f"Loading storage state from {state_file}")
            with open(state_file, 'r') as f:
                storage_state = json.load(f)
            context = await browser.new_context(storage_state=storage_state)
        else:
            context = await browser.new_context()

        page = await context.new_page()
        await apply_anti_detection(page)
        await navigate_and_setup(page, args.thread_url, args.username, args.password, state_file, context)

        page_ref = [page]  # Reference to current page
        pending_page_ref = [None]  # Reference to pending new page
        last_refresh_time_ref = [time.time()]  # Last refresh time
        refresh_task = None  # Track refresh task

        i = 0  # Name index
        while True:
            # --- Add random invisible characters to base name ---
            base_name = names_list[i % len(names_list)]
            
            # Pick 1-3 random invisible chars
            num_invis = random.randint(1, 3)
            invis_text = "".join(random.choice(INVISIBLE_CHARS) for _ in range(num_invis))
            
            # Insert randomly at start, middle, or end
            pos = random.choice([0, len(base_name)//2, len(base_name)])
            new_name = base_name[:pos] + invis_text + base_name[pos:]
            # --- End invisible chars logic ---

            max_retries = 1
            retry_count = 0
            success = False

            while retry_count < max_retries and not success:
                try:
                    logging.debug(f"Starting rename to: {new_name} (attempt {retry_count + 1})")

                    change_locator = page_ref[0].locator("div[role='button'][aria-label='Change group name']")
                    await change_locator.wait_for(timeout=15000)
                    logging.debug("Clicking change group name")
                    try:
                        if not (await change_locator.is_visible() and await change_locator.is_enabled()):
                            logging.debug("Change locator not visible/clickable, attempting to scroll")
                            await change_locator.scroll_into_view_if_needed()
                    except Exception:
                        try:
                            await change_locator.scroll_into_view_if_needed()
                        except Exception:
                            pass

                    await change_locator.click()

                    input_locator = page_ref[0].locator("input[aria-label='Group name']")
                    await input_locator.wait_for(timeout=20000)

                    current_name = await input_locator.input_value()

                    if new_name == current_name:
                        await page_ref[0].keyboard.press('Escape')
                        logging.info(f"Skipped rename to same name: {new_name}")
                        i += 1
                        success = True
                        break

                    await input_locator.fill(new_name)

                    save_locator = page_ref[0].locator("div[role='button']:has-text('Save')")
                    try:
                        await save_locator.wait_for(timeout=15000)
                    except Exception as e_wait:
                        logging.debug(f"Save button not visible: {e_wait}. Retrying.")
                        await page_ref[0].keyboard.press('Escape')
                        retry_count += 1
                        continue

                    try:
                        if not (await save_locator.is_visible() and await save_locator.is_enabled()):
                            await save_locator.scroll_into_view_if_needed()
                        await save_locator.click()
                    except Exception as e_click:
                        logging.debug(f"Normal click failed, trying force: {e_click}")
                        try:
                            await save_locator.click(force=True)
                        except Exception:
                            try:
                                handle = await save_locator.element_handle()
                                if handle:
                                    await page_ref[0].evaluate("(el) => el.click()", handle)
                                else:
                                    raise
                            except Exception as e_js:
                                logging.error(f"Save click failed: {e_js}")
                                raise

                    logging.info(f"Successfully renamed to {new_name}")
                    success = True
                    i += 1

                    # --- NEW TAB SWITCH LOGIC FIXED ---
                    # This section handles the tab switch only after a successful save.
                    # The old tab continues its rename without interruption.
                    # The new tab waits in the background until switch.
                    # Upon switch, track the last saved name from the old tab,
                    # close the old tab, and calculate the next index for the new tab
                    # based on the last_saved_name to continue the sequence seamlessly.
                    # No reload on new tab to maintain speed.
                    if pending_page_ref[0] is not None:
                        logging.info("🔁 Switching to new tab after successful save")
                        # Track the last saved name from the old tab
                        last_saved_name = new_name

                        # Switch references: old becomes pending, but actually switch to new
                        old_page = page_ref[0]
                        page_ref[0] = pending_page_ref[0]
                        pending_page_ref[0] = None
                        await old_page.close()  # Close old tab automatically after save

                        # In new tab, wait for elements without reloading
                        change_locator = page_ref[0].locator("div[role='button'][aria-label='Change group name']")
                        await change_locator.wait_for(timeout=60000)

                        # Read current name in new tab to confirm (optional, but as per logic)
                        await change_locator.click()
                        input_locator = page_ref[0].locator("input[aria-label='Group name']")
                        await input_locator.wait_for(timeout=20000)
                        current_name_new_tab = await input_locator.input_value()
                        await page_ref[0].keyboard.press('Escape')

                        # Calculate next index based on last_saved_name from old tab
                        # This passes the sequence continuity to the new tab
                        try:
                            pos = names_list.index(last_saved_name)
                            i = pos + 1  # Continue from next, without % to avoid unnecessary cycle if not needed, but can add % len if cycling
                            logging.info(f"Switched tab. Last saved: {last_saved_name}, next index: {i}")
                        except ValueError:
                            logging.warning(f"Last saved name {last_saved_name} not in list, keeping index {i}")

                        last_refresh_time_ref[0] = time.time()

                except Exception as e:
                    logging.error(f"Error during rename to {new_name}: {str(e)}")
                    await page_ref[0].keyboard.press('Escape')
                    if 'accounts/login' in page_ref[0].url:
                        if args.password is None:
                            logging.error("Re-login required, no password.")
                            return
                        logging.info("Session expired. Re-logging in.")
                        await perform_login(page_ref[0], args.username, args.password)
                        await context.storage_state(path=state_file)
                        await navigate_and_setup(page_ref[0], args.thread_url, args.username, args.password, state_file, context)
                    logging.warning(f"Rename failed, skipping to next")
                    i += 1
                    break

            if not success:
                logging.error(f"Max retries for {new_name}. Skipping.")
                i += 1

            # --- Background new tab preparation ---
            if time.time() - last_refresh_time_ref[0] >= 30 and pending_page_ref[0] is None and (not refresh_task or refresh_task.done()):
                logging.info("🌀 Triggering background tab preparation")
                refresh_task = asyncio.create_task(prepare_new_tab(context, pending_page_ref, args))

async def navigate_and_setup(page, thread_url, username, password, state_file, context):
    logging.debug(f"Navigating to {thread_url}")
    try:
        await page.goto(thread_url, timeout=60000)
    except Exception as e:
        logging.error(f"Navigation error: {str(e)}")

    if 'accounts/login' in page.url:
        if password is None:
            logging.error("Login required, no password.")
            raise ValueError("Login required but no password provided.")
        logging.info("Performing login.")
        await perform_login(page, username, password)
        try:
            await page.goto(thread_url, timeout=60000)
        except Exception as e:
            logging.error(f"Post-login navigation error: {str(e)}")
        await context.storage_state(path=state_file)
        logging.debug(f"Saved state to {state_file}")

    await setup_details_pane(page)

async def setup_details_pane(page):
    try:
        details_locator = page.locator("div[role='button'][aria-label='Open the details pane of the chat']")
        await details_locator.wait_for(timeout=15000)
        logging.debug("Opening details pane")
        try:
            if not (await details_locator.is_visible() and await details_locator.is_enabled()):
                await details_locator.scroll_into_view_if_needed()
        except Exception:
            try:
                await details_locator.scroll_into_view_if_needed()
            except Exception:
                pass
        await details_locator.click()
        logging.info("Details pane opened")

        watcher_timeout = 0.5
        poll_interval = 0.1
        start_watch = time.time()
        logging.debug("Watching for notifications popup")
        while time.time() - start_watch < watcher_timeout:
            try:
                notif_button = page.locator('button[tabindex="0"]:has-text("Turn On")')
                if await notif_button.count() and await notif_button.is_visible():
                    try:
                        if not await notif_button.is_enabled():
                            await notif_button.scroll_into_view_if_needed()
                            await notif_button.click(force=True)
                        else:
                            await notif_button.click()
                        logging.info("Clicked Turn On notifications")
                        break
                    except Exception as e_click:
                        logging.debug(f"Click failed: {e_click}")
                        try:
                            handle = await notif_button.element_handle()
                            if handle:
                                await page.evaluate("(el) => el.click()", handle)
                                logging.info("JS click on notifications")
                                break
                        except Exception:
                            pass
            except Exception:
                pass
            await asyncio.sleep(poll_interval)

    except Exception as e:
        logging.error(f"Details pane error: {str(e)}")

async def perform_login(page, username, password):
    try:
        await apply_anti_detection(page)

        username_locator = page.locator('input[name="username"]')
        await username_locator.wait_for(state='visible', timeout=10000)
        await username_locator.focus()
        await asyncio.sleep(random.uniform(0.5, 0.5))
        for char in username:
            await username_locator.press(char)
            await asyncio.sleep(random.uniform(0.05, 0.15))

        password_locator = page.locator('input[name="password"]')
        await password_locator.wait_for(state='visible', timeout=10000)
        await asyncio.sleep(random.uniform(0.5, 1.5))
        await password_locator.focus()
        await asyncio.sleep(random.uniform(0.3, 0.8))
        for char in password:
            await password_locator.press(char)
            await asyncio.sleep(random.uniform(0.05, 0.15))

        await asyncio.sleep(random.uniform(0.5, 1.5))

        submit_locator = page.locator('button[type="submit"]')
        await submit_locator.wait_for(state='visible', timeout=10000)
        if not await submit_locator.is_enabled():
            raise Exception("Submit not enabled")
        await submit_locator.click()

        try:
            await page.wait_for_url(lambda url: 'accounts/login' not in url and 'challenge' not in url and 'two_factor' not in url, timeout=60000)
            if await page.locator('[role="alert"]').count() > 0:
                error_text = (await page.locator('[role="alert"]').inner_text()).lower()
                if 'incorrect' in error_text or 'wrong' in error_text:
                    raise ValueError("ERROR_001: Invalid credentials")
                elif 'wait' in error_text or 'few minutes' in error_text or 'too many' in error_text:
                    raise ValueError("ERROR_002: Rate limit exceeded")
                else:
                    raise ValueError(f"ERROR_003: Login error - {error_text}")
        except TimeoutError:
            current_url = page.url
            page_content = (await page.content()).lower()
            if 'challenge' in current_url:
                raise ValueError("ERROR_004: Login challenge required")
            elif 'two_factor' in current_url or 'verify' in current_url:
                raise ValueError("ERROR_005: 2FA verification required")
            elif '429' in page_content or 'rate limit' in page_content or 'too many requests' in page_content:
                raise ValueError("ERROR_002: Rate limit exceeded")
            elif await page.locator('[role="alert"]').count() > 0:
                error_text = (await page.locator('[role="alert"]').inner_text()).lower()
                raise ValueError(f"ERROR_006: Login failed - {error_text}")
            else:
                raise ValueError("ERROR_007: Login timeout or unknown error")

        logging.info("Login successful")
    except Exception as e:
        logging.error(f"Login failed: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())