import argparse
import json
import os
import time
import random
import logging
import sqlite3
import re
from playwright.sync_api import sync_playwright
import urllib.parse
import subprocess
import pty
import errno
import sys
from typing import Dict, List
import threading
import uuid
import signal
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler, ContextTypes, CallbackQueryHandler
from telegram.error import Forbidden, BadRequest
import asyncio
from dotenv import load_dotenv
from playwright_stealth import stealth_sync
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, TwoFactorRequired, PleaseWaitFewMinutes, RateLimitError, LoginRequired

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('instagram_gc_renamer.log'),
        logging.StreamHandler()
    ]
)

AUTHORIZED_FILE = 'authorized_users.json'
TASKS_FILE = 'tasks.json'
OWNER_TG_ID = int(os.environ.get('OWNER_TG_ID'))
BOT_TOKEN = os.environ.get('BOT_TOKEN')
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# 🎯 FORCE JOIN CHANNELS - Add your channel usernames here (without @)
REQUIRED_CHANNELS = [
    "your_channel_1",  # Replace with your actual channel username
    "your_channel_2",  # Add more channels as needed
]

authorized_users = []
users_data: Dict[int, Dict] = {}
users_pending: Dict[int, Dict] = {}
users_tasks: Dict[int, List[Dict]] = {}
persistent_tasks = []

os.makedirs('sessions', exist_ok=True)

# === PATCH: Fix instagrapi invalid timestamp bug ===
def _sanitize_timestamps(obj):
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            if isinstance(v, int) and k.endswith("_timestamp_us"):
                try:
                    secs = int(v) // 1_000_000
                except Exception:
                    secs = None
                if secs is None or secs < 0 or secs > 4102444800:
                    new_obj[k] = None
                else:
                    new_obj[k] = secs
            else:
                new_obj[k] = _sanitize_timestamps(v)
        return new_obj
    elif isinstance(obj, list):
        return [_sanitize_timestamps(i) for i in obj]
    else:
        return obj

try:
    import instagrapi.extractors as extractors
    _orig_extract_reply_message = extractors.extract_reply_message

    def patched_extract_reply_message(data):
        data = _sanitize_timestamps(data)
        return _orig_extract_reply_message(data)

    extractors.extract_reply_message = patched_extract_reply_message
    print("[Patch] Applied timestamp sanitizer to instagrapi extractors ✅")
except Exception as e:
    print(f"[Patch Warning] Could not patch instagrapi: {e}")

def run_with_sync_playwright(fn, *args, **kwargs):
    result = {"value": None, "exc": None}

    def target():
        try:
            with sync_playwright() as p:
                result["value"] = fn(p, *args, **kwargs)
        except Exception as e:
            result["exc"] = e

    t = threading.Thread(target=target)
    t.start()
    t.join()
    if result["exc"]:
        raise result["exc"]
    return result["value"]

def load_authorized():
    global authorized_users
    if os.path.exists(AUTHORIZED_FILE):
        with open(AUTHORIZED_FILE, 'r') as f:
            authorized_users = json.load(f)
    if not any(u['id'] == OWNER_TG_ID for u in authorized_users):
        authorized_users.append({'id': OWNER_TG_ID, 'username': 'owner'})

load_authorized()

def load_users_data():
    global users_data
    users_data = {}
    for file in os.listdir('.'):
        if file.startswith('user_') and file.endswith('.json'):
            user_id_str = file[5:-5]
            if user_id_str.isdigit():
                user_id = int(user_id_str)
                with open(file, 'r') as f:
                    users_data[user_id] = json.load(f)

load_users_data()

def save_authorized():
    with open(AUTHORIZED_FILE, 'w') as f:
        json.dump(authorized_users, f)

def save_user_data(user_id: int, data: Dict):
    with open(f'user_{user_id}.json', 'w') as f:
        json.dump(data, f)

def is_authorized(user_id: int) -> bool:
    return any(u['id'] == user_id for u in authorized_users)

def is_owner(user_id: int) -> bool:
    return user_id == OWNER_TG_ID

def future_expiry(days=365):
    return int(time.time()) + days*24*3600

def convert_for_playwright(insta_file, playwright_file):
    try:
        with open(insta_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        return

    cookies = []
    auth = data.get("authorization_data", {})
    for name, value in auth.items():
        cookies.append({
            "name": name,
            "value": urllib.parse.unquote(value),
            "domain": ".instagram.com",
            "path": "/",
            "expires": future_expiry(),
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })

    playwright_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }

    with open(playwright_file, "w") as f:
        json.dump(playwright_state, f, indent=4)

def get_storage_state_from_instagrapi(settings: Dict):
    cl = Client()
    cl.set_settings(settings)

    cookies_dict = {}
    if hasattr(cl, "session") and cl.session:
        try:
            cookies_dict = cl.session.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "private") and hasattr(cl.private, "cookies"):
        try:
            cookies_dict = cl.private.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "_http") and hasattr(cl._http, "cookies"):
        try:
            cookies_dict = cl._http.cookies.get_dict()
        except Exception:
            cookies_dict = {}

    cookies = []
    for name, value in cookies_dict.items():
        cookies.append({
            "name": name,
            "value": value,
            "domain": ".instagram.com",
            "path": "/",
            "expires": int(time.time()) + 365*24*3600,
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })

    storage_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }
    return storage_state

def instagrapi_login(username, password):
    cl = Client()
    session_file = f"{username}_session.json"
    playwright_file = f"{username}_state.json"
    try:
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
    except (ChallengeRequired, TwoFactorRequired):
        raise ValueError("ERROR_004: Login challenge or 2FA required")
    except (PleaseWaitFewMinutes, RateLimitError):
        raise ValueError("ERROR_002: Rate limit exceeded")
    except Exception as e:
        raise ValueError(f"ERROR_007: Login failed - {str(e)}")
    return json.load(open(playwright_file))

def list_group_chats(user_id, storage_state, username, password, max_groups=10, last_n_threads=10):
    session_file = f"sessions/{user_id}_{username}_session.json"
    playwright_file = f"sessions/{user_id}_{username}_state.json"
    cl = Client()
    updated = False
    new_state = None

    if os.path.exists(session_file):
        try:
            cl.load_settings(session_file)
        except Exception:
            pass

    try:
        threads = cl.direct_threads(amount=last_n_threads)
        time.sleep(random.uniform(1.0, 3.0))
    except LoginRequired:
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
        updated = True
        threads = cl.direct_threads(amount=last_n_threads)
        time.sleep(random.uniform(1.0, 3.0))

    groups = []
    for thread in threads:
        if len(groups) >= max_groups:
            break
        if getattr(thread, "is_group", False):
            member_count = len(getattr(thread, "users", [])) + 1
            if member_count < 3:
                continue

            title = getattr(thread, "thread_title", None) or getattr(thread, "title", None)
            if not title or title.strip() == "":
                try:
                    users_part = ", ".join([u.username for u in getattr(thread, "users", [])][:3])
                    display = users_part if users_part else "<no name>"
                except Exception:
                    display = "<no name>"
            else:
                display = title

            url = f"https://www.instagram.com/direct/t/{getattr(thread, 'thread_id', getattr(thread, 'id', 'unknown'))}"
            groups.append({'display': display, 'url': url})

    if updated and os.path.exists(playwright_file):
        new_state = json.load(open(playwright_file))
    else:
        new_state = storage_state

    return groups, new_state

def perform_login(page, username, password):
    try:
        page.evaluate("""() => {
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

        username_locator = page.locator('input[name="username"]')
        username_locator.wait_for(state='visible', timeout=10000)
        username_locator.focus()
        time.sleep(random.uniform(0.5, 1.5))
        for char in username:
            username_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        password_locator = page.locator('input[name="password"]')
        password_locator.wait_for(state='visible', timeout=10000)
        time.sleep(random.uniform(0.5, 1.5))
        password_locator.focus()
        time.sleep(random.uniform(0.3, 0.8))
        for char in password:
            password_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        time.sleep(random.uniform(1.0, 2.5))

        submit_locator = page.locator('button[type="submit"]')
        submit_locator.wait_for(state='visible', timeout=10000)
        if not submit_locator.is_enabled():
            raise Exception("Submit button not enabled")
        submit_locator.click()

        try:
            page.wait_for_url(lambda url: 'accounts/login' not in url and 'challenge' not in url and 'two_factor' not in url, timeout=60000)
            
            if page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                if 'incorrect' in error_text or 'wrong' in error_text:
                    raise ValueError("ERROR_001: Invalid credentials")
                elif 'wait' in error_text or 'few minutes' in error_text or 'too many' in error_text:
                    raise ValueError("ERROR_002: Rate limit exceeded")
                else:
                    raise ValueError(f"ERROR_003: Login error - {error_text}")
        except TimeoutError:
            current_url = page.url
            page_content = page.content().lower()
            if 'challenge' in current_url:
                raise ValueError("ERROR_004: Login challenge required")
            elif 'two_factor' in current_url or 'verify' in current_url:
                raise ValueError("ERROR_005: 2FA verification required")
            elif '429' in page_content or 'rate limit' in page_content or 'too many requests' in page_content:
                raise ValueError("ERROR_002: Rate limit exceeded")
            elif page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                raise ValueError(f"ERROR_006: Login failed - {error_text}")
            else:
                raise ValueError("ERROR_007: Login timeout or unknown error")

        logging.info("Login successful")
    except Exception as e:
        logging.error(f"Login failed: {str(e)}")
        raise

APP = None
LOOP = None
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

def child_login(user_id: int, username: str, password: str):
    cl = Client()
    session_file = f"sessions/{user_id}_{username}_session.json"
    playwright_file = f"sessions/{user_id}_{username}_state.json"
    try:
        print(f"[{username}] ⚙️ Attempting login.. if you are stucked here check your gmail or messages check for otp and enter otp here eg: 192122.")
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
        print(f"[{username}] ✅ Logged in successfully. Session saved: {session_file}")
    except TwoFactorRequired:
        print(f" Enter code (6 digits) for {username} (2FA): ", end="", flush=True)
        otp = input().strip()
        try:
            cl.login(username, password, verification_code=otp)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            print(f"[{username}] ✅ OTP resolved. Logged in. Session saved: {session_file}")
        except Exception as e:
            print(f"[{username}] ❌ OTP failed: {e}")
    except ChallengeRequired:
        print(f" Enter code (6 digits) for {username} (Challenge): ", end="", flush=True)
        otp = input().strip()
        try:
            cl.challenge_resolve(cl.last_json, security_code=otp)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            print(f"[{username}] ✅ OTP resolved. Logged in. Session saved: {session_file}")
        except Exception as e:
            print(f"[{username}] ❌ OTP failed: {e}")
    except Exception as e:
        print(f"[{username}] ❌ Login failed: {e}")
    finally:
        time.sleep(0.5)
        sys.exit(0)

def reader_thread(user_id: int, chat_id: int, master_fd: int, username: str, password: str):
    global APP, LOOP
    buf = b""
    while True:
        try:
            data = os.read(master_fd, 1024)
            if not data:
                break
            buf += data
            while b"\n" in buf or len(buf) > 2048:
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode(errors="ignore").strip()
                else:
                    text = buf.decode(errors="ignore")
                    buf = b""
                if not text:
                    continue
                if text.startswith("Code entered"):
                    continue
                lower = text.lower()
                if (
                    len(text) > 300
                    or "cdninstagram.com" in lower
                    or "http" in lower
                    or "{" in text
                    or "}" in text
                    or "debug" in lower
                    or "info" in lower
                    or "urllib3" in lower
                    or "connection" in lower
                    or "starting new https" in lower
                    or "instagrapi" in lower
                ):
                    continue
                try:
                    if APP and LOOP:
                        asyncio.run_coroutine_threadsafe(
                            APP.bot.send_message(chat_id=chat_id, text=f"🔥{text}"), LOOP
                        )
                except Exception:
                    logging.error("[THREAD] send_message failed")
        except OSError as e:
            if e.errno == errno.EIO:
                break
            else:
                logging.error("[THREAD] PTY read error: %s", e)
                break
        except Exception as e:
            logging.error("[THREAD] Unexpected error: %s", e)
            break
    try:
        playwright_file = f"sessions/{user_id}_{username}_state.json"
        if os.path.exists(playwright_file):
            with open(playwright_file, 'r') as f:
                state = json.load(f)
            if user_id in users_data:
                data = users_data[user_id]
            else:
                data = {'accounts': [], 'default': None}
            for i, acc in enumerate(data['accounts']):
                if acc['ig_username'] == username:
                    data['accounts'][i] = {'ig_username': username, 'password': password, 'storage_state': state}
                    data['default'] = i
                    break
            else:
                data['accounts'].append({'ig_username': username, 'password': password, 'storage_state': state})
                data['default'] = len(data['accounts']) - 1
            save_user_data(user_id, data)
            users_data[user_id] = data
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="✅ Login successful and saved securely! 🎉"), LOOP)
        else:
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="⚠️ Login failed. No session saved."), LOOP)
    except Exception as e:
        logging.error("Failed to save user data: %s", e)
        if APP and LOOP:
            asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text=f"⚠️ Error saving data: {str(e)}"), LOOP)
    finally:
        with SESSIONS_LOCK:
            if user_id in SESSIONS:
                try:
                    os.close(SESSIONS[user_id]["master_fd"])
                except Exception:
                    pass
                SESSIONS.pop(user_id, None)

async def relay_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        return
    master_fd = info["master_fd"]
    try:
        os.write(master_fd, (text + "\n").encode())
    except OSError as e:
        await update.message.reply_text(f"Failed to write to PTY stdin: {e}")
    except Exception as e:
        logging.error("Relay input error: %s", e)

async def cmd_kill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        await update.message.reply_text("🚫 No active PTY session.")
        return
    pid = info["pid"]
    master_fd = info["master_fd"]
    try:
        os.kill(pid, 15)
    except Exception:
        pass
    try:
        os.close(master_fd)
    except Exception:
        pass
    with SESSIONS_LOCK:
        SESSIONS.pop(user_id, None)
    await update.message.reply_text(f"🛑 Stopped login terminal (pid={pid}) successfully.")

async def flush(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ You are not an admin ⚠️")
        return
    global users_tasks, persistent_tasks
    count = 0
    for uid, tasks in users_tasks.items():
        for task in tasks[:]:
            proc = task['proc']
            proc.terminate()
            await asyncio.sleep(3)
            if proc.poll() is None:
                proc.kill()
            logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task stop user={uid} task={task['id']} url={task['thread_url']} by flush")
            mark_task_stopped_persistent(task['id'])
            tasks.remove(task)
            count += 1
        users_tasks[uid] = tasks
    await update.message.reply_text(f"🧹 Flushed {count} tasks globally! 🛑")

# 🎯 FORCE JOIN CHECK
async def check_user_joined_channels(user_id: int, context: ContextTypes.DEFAULT_TYPE) -> tuple:
    """Check if user joined all required channels. Returns (is_joined, missing_channels)"""
    if not REQUIRED_CHANNELS or REQUIRED_CHANNELS == ["your_channel_1", "your_channel_2"]:
        return True, []  # No channels configured
    
    missing = []
    for channel in REQUIRED_CHANNELS:
        try:
            member = await context.bot.get_chat_member(f"@{channel}", user_id)
            if member.status in ['left', 'kicked']:
                missing.append(channel)
        except Exception as e:
            logging.error(f"Error checking channel {channel}: {e}")
            missing.append(channel)
    
    return len(missing) == 0, missing

async def send_join_channels_message(update: Update, missing_channels: List[str]):
    """Send message with buttons to join required channels"""
    keyboard = []
    for channel in missing_channels:
        keyboard.append([InlineKeyboardButton(f"📢 Join @{channel}", url=f"https://t.me/{channel}")])
    keyboard.append([InlineKeyboardButton("✅ I Joined!", callback_data="check_joined")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🚫 *Access Denied!* 🚫\n\n"
        "😈 You need to join our channels first to use this bot!\n\n"
        "👇 Click the buttons below to join:",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

async def check_joined_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle 'I Joined!' button callback"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    is_joined, missing = await check_user_joined_channels(user_id, context)
    
    if is_joined:
        await query.edit_message_text("✅ *Verification Successful!* ✅\n\n🎉 Welcome! You can now use the bot.\n\nType /help to see available commands.", parse_mode="Markdown")
    else:
        await query.answer("❌ You haven't joined all channels yet!", show_alert=True)

# 📢 BROADCAST COMMAND
BROADCAST_MESSAGE = range(1)

async def broadcast_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ You are not an admin ⚠️")
        return ConversationHandler.END
    
    await update.message.reply_text(
        "📢 *Broadcast Message* 📢\n\n"
        "Send the message you want to broadcast to all authorized users.\n\n"
        "💡 You can send text, photos, videos, or documents.\n"
        "Type /cancel to cancel.",
        parse_mode="Markdown"
    )
    return BROADCAST_MESSAGE

async def broadcast_execute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    
    # Store the message to broadcast
    context.user_data['broadcast_msg'] = update.message
    
    # Get all authorized users
    target_users = [u['id'] for u in authorized_users if u['id'] != user_id]
    
    if not target_users:
        await update.message.reply_text("❌ No users to broadcast to!")
        return ConversationHandler.END
    
    progress_msg = await update.message.reply_text(f"📤 Broadcasting to {len(target_users)} users...\n\n⏳ Progress: 0/{len(target_users)}")
    
    success = 0
    failed = 0
    blocked = 0
    
    for idx, target_id in enumerate(target_users, 1):
        try:
            # Forward the message type
            if update.message.text:
                await context.bot.send_message(chat_id=target_id, text=f"📢 *Broadcast from Admin:*\n\n{update.message.text}", parse_mode="Markdown")
            elif update.message.photo:
                await context.bot.send_photo(chat_id=target_id, photo=update.message.photo[-1].file_id, caption=f"📢 Broadcast from Admin\n\n{update.message.caption or ''}")
            elif update.message.video:
                await context.bot.send_video(chat_id=target_id, video=update.message.video.file_id, caption=f"📢 Broadcast from Admin\n\n{update.message.caption or ''}")
            elif update.message.document:
                await context.bot.send_document(chat_id=target_id, document=update.message.document.file_id, caption=f"📢 Broadcast from Admin\n\n{update.message.caption or ''}")
            
            success += 1
        except Forbidden:
            blocked += 1
        except Exception as e:
            logging.error(f"Broadcast error for user {target_id}: {e}")
            failed += 1
        
        # Update progress every 5 users
        if idx % 5 == 0 or idx == len(target_users):
            try:
                await progress_msg.edit_text(f"📤 Broadcasting to {len(target_users)} users...\n\n⏳ Progress: {idx}/{len(target_users)}")
            except:
                pass
        
        await asyncio.sleep(0.1)  # Rate limit prevention
    
    await progress_msg.edit_text(
        f"✅ *Broadcast Complete!* ✅\n\n"
        f"📊 Statistics:\n"
        f"✅ Success: {success}\n"
        f"🚫 Blocked: {blocked}\n"
        f"❌ Failed: {failed}\n"
        f"📝 Total: {len(target_users)}",
        parse_mode="Markdown"
    )
    
    return ConversationHandler.END

async def broadcast_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("🚫 Broadcast cancelled.")
    return ConversationHandler.END

USERNAME, PASSWORD = range(2)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return
    
    welcome_text = (
        "🎭 *Welcome to Jerry's GC Renamer Bot!* 🎭\n\n"
        "🔥 The ultimate Instagram group chat spam tool! 🔥\n\n"
        "💀 Features:\n"
        "• Rapid GC name changes\n"
        "• Multiple account support\n"
        "• Task management\n"
        "• Auto session handling\n\n"
        "👉 Type /help to see all commands!"
    )
    await update.message.reply_text(welcome_text, parse_mode="Markdown")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return
    
    help_text = (
        "🎮 *Jerry's GC Renamer - Command List* 🎮\n\n"
        "👤 *User Commands:*\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        "/help ⚡ - Show this help menu\n"
        "/login 📱 - Login to Instagram account\n"
        "/viewmyac 👀 - View your saved accounts\n"
        "/setig 🔄 <number> - Set default account\n"
        "/attack 💥 - Start renaming task\n"
        "/stop 🛑 - Stop your tasks\n"
        "/task 📋 - View ongoing tasks\n"
        "/logout 🚪 <username> - Logout and remove account\n"
        "/kill 🔪 - Kill active login session\n\n"
    )
    
    if is_owner(user_id):
        help_text += (
            "👑 *Admin Commands:*\n"
            "━━━━━━━━━━━━━━━━━━━\n"
            "/add ➕ <tg_id> - Add authorized user\n"
            "/remove ➖ <tg_id> - Remove authorized user\n"
            "/users 📜 - List authorized users\n"
            "/broadcast 📢 - Broadcast message to all users\n"
            "/flush 🧹 - Stop all tasks globally\n\n"
        )
    
    help_text += "💀 *Made with chaos by Jerry* 💀"
    
    await update.message.reply_text(help_text, parse_mode="Markdown")

async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return ConversationHandler.END
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return ConversationHandler.END
    await update.message.reply_text("📱 *Login to Instagram* 📱\n\nEnter your Instagram username:", parse_mode="Markdown")
    return USERNAME

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['ig_username'] = update.message.text.strip()
    await update.message.reply_text("🔒 *Enter your password:* 🔒\n\n🛡️ Your password is encrypted and secure!", parse_mode="Markdown")
    return PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    username = context.user_data['ig_username']
    password = update.message.text.strip()
    
    with SESSIONS_LOCK:
        if user_id in SESSIONS:
            await update.message.reply_text("⚠️ PTY session already running. Use /kill first.")
            return ConversationHandler.END

    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            child_login(user_id, username, password)
        except SystemExit:
            os._exit(0)
        except Exception as e:
            print(f"[CHILD] Unexpected error: {e}")
            os._exit(1)
    else:
        t = threading.Thread(target=reader_thread, args=(user_id, chat_id, master_fd, username, password), daemon=True)
        t.start()
        with SESSIONS_LOCK:
            SESSIONS[user_id] = {"pid": pid, "master_fd": master_fd, "thread": t, "username": username, "password": password, "chat_id": chat_id}
        
    return ConversationHandler.END

async def viewmyac(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return
    if user_id not in users_data:
        await update.message.reply_text("❌ You haven't saved any account. Use /login to save one. ❌")
        return
    data = users_data[user_id]
    msg = "👀 *Your Saved Accounts* 👀\n━━━━━━━━━━━━━━━━━━━\n"
    for i, acc in enumerate(data['accounts']):
        default = " ⭐ (default)" if data['default'] == i else ""
        msg += f"{i+1}. 📱 {acc['ig_username']}{default}\n"
    msg += "\n💡 Use /setig <number> to set default"
    await update.message.reply_text(msg, parse_mode="Markdown")

async def setig(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("❗ Usage: /setig <number> ❗")
        return
    num = int(context.args[0]) - 1
    if user_id not in users_data:
        await update.message.reply_text("❌ No accounts saved. ❌")
        return
    data = users_data[user_id]
    if num < 0 or num >= len(data['accounts']):
        await update.message.reply_text("⚠️ Invalid number. ⚠️")
        return
    data['default'] = num
    save_user_data(user_id, data)
    acc = data['accounts'][num]['ig_username']
    await update.message.reply_text(f"✅ *Default Account Set!* ✅\n\n⭐ {num+1}. {acc}", parse_mode="Markdown")

async def logout_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return
    if not context.args:
        await update.message.reply_text("❗ Usage: /logout <username> ❗")
        return
    username = context.args[0].strip()
    if user_id not in users_data:
        await update.message.reply_text("❌ No accounts saved. ❌")
        return
    data = users_data[user_id]
    for i, acc in enumerate(data['accounts']):
        if acc['ig_username'] == username:
            del data['accounts'][i]
            if data['default'] == i:
                data['default'] = 0 if data['accounts'] else None
            elif data['default'] > i:
                data['default'] -= 1
            break
    else:
        await update.message.reply_text("⚠️ Account not found. ⚠️")
        return
    save_user_data(user_id, data)
    session_file = f"sessions/{user_id}_{username}_session.json"
    state_file = f"sessions/{user_id}_{username}_state.json"
    if os.path.exists(session_file):
        os.remove(session_file)
    if os.path.exists(state_file):
        os.remove(state_file)
    await update.message.reply_text(f"✅ *Logged out!* ✅\n\n🚪 Removed {username} and deleted all files.", parse_mode="Markdown")

SELECT_THREAD, NAMES = range(2)

def load_persistent_tasks():
    global persistent_tasks
    if os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, 'r') as f:
            persistent_tasks = json.load(f)
    else:
        persistent_tasks = []

def save_persistent_tasks():
    global persistent_tasks
    with open(TASKS_FILE, 'w') as f:
        json.dump(persistent_tasks, f)

def mark_task_stopped_persistent(task_id: str):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['status'] = 'stopped'
            save_persistent_tasks()
            break

def update_task_pid_persistent(task_id: str, new_pid: int):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['pid'] = new_pid
            save_persistent_tasks()
            break

def mark_task_completed_persistent(task_id: str):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['status'] = 'completed'
            save_persistent_tasks()
            break

def restore_tasks_on_start():
    load_persistent_tasks()
    print(f"🔄 Restoring {len([t for t in persistent_tasks if t['status'] == 'running'])} running tasks...")
    
    for task in persistent_tasks[:]:
        if task['status'] == 'running':
            old_pid = task['pid']
            try:
                os.kill(old_pid, signal.SIGTERM)
                time.sleep(1)
            except OSError:
                pass
            
            try:
                proc = subprocess.Popen(task['cmd'])
                new_pid = proc.pid
                update_task_pid_persistent(task['id'], new_pid)
                
                mem_task = task.copy()
                mem_task['proc'] = proc
                user_id = task['user_id']
                if user_id not in users_tasks:
                    users_tasks[user_id] = []
                users_tasks[user_id].append(mem_task)
                
                print(f"✅ Restored task {task['id']} for {task['gc_display']} | New PID: {new_pid}")
                
            except Exception as e:
                logging.error(f"❌ Failed to restore task {task['id']}: {e}")
                mark_task_stopped_persistent(task['id'])
    
    save_persistent_tasks()
    print("✅ Task restoration complete!")

async def send_resume_notification(user_id: int, task: Dict):
    try:
        await APP.bot.send_message(
            chat_id=user_id, 
            text=f"🔄 The attack on '{task['gc_display']}' was automatically resumed. New PID: {task['pid']}"
        )
    except Exception as e:
        logging.error(f"Failed to send resume notification to {user_id}: {e}")

async def attack_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return ConversationHandler.END
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return ConversationHandler.END
    if user_id not in users_data:
        await update.message.reply_text("❗ Please /login first. ❗")
        return ConversationHandler.END
    data = users_data[user_id]
    if data['default'] is None:
        await update.message.reply_text("⚠️ No default account set. Use /login or /setig. ⚠️")
        return ConversationHandler.END
    account = data['accounts'][data['default']]
    await update.message.reply_text("🔍 *Fetching your last 10 GC threads...* 🔍\n\n⏳ Please wait...", parse_mode="Markdown")
    groups, new_state = await asyncio.to_thread(list_group_chats, user_id, account['storage_state'], account['ig_username'], account['password'])
    if new_state != account['storage_state']:
        account['storage_state'] = new_state
        save_user_data(user_id, data)
    if not groups:
        await update.message.reply_text("❌ No group chats found. ❌")
        return ConversationHandler.END
    msg = "📢 *Select a thread by number:* 📢\n━━━━━━━━━━━━━━━━━━━\n"
    for i, g in enumerate(groups):
        msg += f"{i+1}. 💬 {g['display']}\n"
    msg += "\n💡 You can select multiple: 1,2,3"
    await update.message.reply_text(msg, parse_mode="Markdown")
    context.user_data['groups'] = groups
    return SELECT_THREAD

async def select_thread(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text.strip()
    num_strs = [n.strip() for n in text.split(',') if n.strip()]
    try:
        nums = [int(n) - 1 for n in num_strs]
        if not nums:
            raise ValueError
    except ValueError:
        await update.message.reply_text("⚠️ Invalid selection. Send numbers like: 1 or 1,2,3")
        return SELECT_THREAD
    groups = context.user_data.get('groups', [])
    if any(n < 0 or n >= len(groups) for n in nums):
        await update.message.reply_text("⚠️ Invalid selection. Send numbers like: 1 or 1,2,3")
        return SELECT_THREAD
    selected_gcs = [groups[n] for n in nums]
    context.user_data['selected_gcs'] = selected_gcs
    await update.message.reply_text("📝 *Send names in this format:*\n\ngroup 1,group 2,group 3\n\n💡 Optional: Add --headless false to see browser", parse_mode="Markdown")
    return NAMES

async def get_names(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text.strip()
    headless = "true"
    if "--headless false" in text.lower():
        headless = "false"
    text = re.sub(r'--headless\s+(true|false)', '', text, flags=re.I)
    names_list = [n.strip() for n in re.split(r'[,\n]', text) if n.strip()]
    names_str = ','.join(names_list)
    if len(names_str) > 1024:
        await update.message.reply_text("⚠️ Names too long; shorten the list.")
        return NAMES
    if not names_list:
        await update.message.reply_text("⚠️ No names provided. Send names like: group 1,group 2,group 3")
        return NAMES
    if not os.path.isfile('ig.py'):
        await update.message.reply_text("⚠️ ig.py not found or not executable.")
        return ConversationHandler.END
    data = users_data[user_id]
    account = data['accounts'][data['default']]
    if 'storage_state' not in account:
        await update.message.reply_text("⚠️ Selected IG account has no saved session. Please /login or choose another account.")
        return ConversationHandler.END
    username = account['ig_username']
    state_file = f"sessions/{user_id}_{username}_state.json"
    if not os.path.exists(state_file):
        with open(state_file, 'w') as f:
            json.dump(account['storage_state'], f)
    tasks = users_tasks.get(user_id, [])
    if len(tasks) >= 5:
        await update.message.reply_text("⚠️ You have reached the max limit (5) of active tasks. Stop one before starting new. ⚠️")
        return ConversationHandler.END
    selected_gcs = context.user_data['selected_gcs']
    for selected in selected_gcs:
        thread_url = selected['url']
        task_id = str(uuid.uuid4())
        cmd = ["python3", "ig.py", "--username", username, "--thread-url", thread_url, "--names", names_str, "--headless", headless, "--storage-state", state_file]

        proc = subprocess.Popen(cmd)
        pid = proc.pid

        new_task = {
            "id": task_id,
            "user_id": user_id,
            "gc_display": selected['display'],
            "account": username,
            "thread_url": thread_url,
            "cmd": cmd,
            "pid": pid,
            "status": "running",
            "start_time": time.time()
        }
        persistent_tasks.append(new_task)
        save_persistent_tasks()
        mem_task = new_task.copy()
        mem_task['proc'] = proc
        tasks.append(mem_task)
        logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task start user={user_id} task={task_id} url={thread_url} cmd={' '.join(cmd)}")

        await update.message.reply_text(
            f"💥 *Attack Launched!* 💥\n\n"
            f"🎯 Target: {selected['display']}\n"
            f"🔢 PID: {pid}\n\n"
            f"🛑 To stop: /stop {pid}",
            parse_mode="Markdown"
        )

    users_tasks[user_id] = tasks
    return ConversationHandler.END

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return
    if not context.args:
        await update.message.reply_text("❗ Usage: /stop <PID> or /stop all ❗")
        return
    arg = context.args[0]
    if user_id not in users_tasks or not users_tasks[user_id]:
        await update.message.reply_text("❌ No tasks running. ❌")
        return
    tasks = users_tasks[user_id]
    if arg == 'all':
        count = len(tasks)
        for task in tasks[:]:
            proc = task['proc']
            proc.terminate()
            await asyncio.sleep(3)
            if proc.poll() is None:
                proc.kill()
            logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task stop user={user_id} task={task['id']} url={task['thread_url']}")
            mark_task_stopped_persistent(task['id'])
            tasks.remove(task)
        await update.message.reply_text(f"🛑 *Stopped {count} tasks!* 🛑", parse_mode="Markdown")
    elif arg.isdigit():
        pid = int(arg)
        for task in tasks[:]:
            if task.get('pid') == pid:
                proc = task['proc']
                proc.terminate()
                await asyncio.sleep(3)
                if proc.poll() is None:
                    proc.kill()
                logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task stop user={user_id} task={task['id']} url={task['thread_url']}")
                mark_task_stopped_persistent(task['id'])
                tasks.remove(task)
                await update.message.reply_text(f"🛑 *Stopped task {pid}!* 🛑", parse_mode="Markdown")
                return
        await update.message.reply_text("⚠️ Task not found. ⚠️")
    else:
        await update.message.reply_text("❗ Usage: /stop <PID> or /stop all ❗")
    users_tasks[user_id] = tasks

async def task_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    # Check force join
    is_joined, missing = await check_user_joined_channels(user_id, context)
    if not is_joined:
        await send_join_channels_message(update, missing)
        return
    
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @Darkj35ry")
        return
    if user_id not in users_tasks or not users_tasks[user_id]:
        await update.message.reply_text("❌ No ongoing tasks. ❌")
        return
    tasks = users_tasks[user_id]
    active_tasks = []
    for t in tasks:
        if t['proc'].poll() is None:
            active_tasks.append(t)
        else:
            mark_task_completed_persistent(t['id'])
    users_tasks[user_id] = active_tasks
    msg = "📋 *Ongoing Tasks* 📋\n━━━━━━━━━━━━━━━━━━━\n"
    for task in active_tasks:
        preview = task['gc_display'][:20] if len(task['gc_display']) > 20 else task['gc_display']
        runtime = int(time.time() - task['start_time'])
        msg += f"🔢 PID: {task['pid']}\n💬 {preview}\n⏱️ Runtime: {runtime}s\n\n"
    await update.message.reply_text(msg, parse_mode="Markdown")

async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ You are not an admin ⚠️")
        return
    if len(context.args) != 1:
        await update.message.reply_text("❗ Usage: /add <tg_id> ❗")
        return
    try:
        tg_id = int(context.args[0])
        if any(u['id'] == tg_id for u in authorized_users):
            await update.message.reply_text("❗ User already added. ❗")
            return
        authorized_users.append({'id': tg_id, 'username': ''})
        save_authorized()
        await update.message.reply_text(f"➕ *Added user {tg_id}* ➕\n\n✅ They can now use the bot!", parse_mode="Markdown")
    except:
        await update.message.reply_text("⚠️ Invalid tg_id. ⚠️")

async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ You are not an admin ⚠️")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("❗ Usage: /remove <tg_id> ❗")
        return
    tg_id = int(context.args[0])
    global authorized_users
    authorized_users = [u for u in authorized_users if u['id'] != tg_id]
    save_authorized()
    await update.message.reply_text(f"➖ *Removed user {tg_id}* ➖", parse_mode="Markdown")

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ You are not an admin ⚠️")
        return
    if not authorized_users:
        await update.message.reply_text("❌ No authorized users. ❌")
        return
    msg = "📜 *Authorized Users* 📜\n━━━━━━━━━━━━━━━━━━━\n"
    for i, u in enumerate(authorized_users, 1):
        if u['id'] == OWNER_TG_ID:
            msg += f"{i}. 👑 {u['id']} (owner)\n"
        elif u['username']:
            msg += f"{i}. 👤 @{u['username']} ({u['id']})\n"
        else:
            msg += f"{i}. 👤 {u['id']}\n"
    msg += f"\n📊 Total: {len(authorized_users)} users"
    await update.message.reply_text(msg, parse_mode="Markdown")

def main_bot():
    from telegram.request import HTTPXRequest
    request = HTTPXRequest(connect_timeout=30, read_timeout=30, write_timeout=30)
    application = Application.builder().token(BOT_TOKEN).request(request).build()
    global APP, LOOP
    APP = application
    LOOP = asyncio.get_event_loop()
    
    restore_tasks_on_start()
    
    async def post_init(app):
        for user_id, tasks in users_tasks.items():
            for task in tasks:
                if task['status'] == 'running':
                    await send_resume_notification(user_id, task)
    
    application.post_init = post_init

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("viewmyac", viewmyac))
    application.add_handler(CommandHandler("setig", setig))
    application.add_handler(CommandHandler("stop", stop))
    application.add_handler(CommandHandler("task", task_command))
    application.add_handler(CommandHandler("taks", task_command))
    application.add_handler(CommandHandler("add", add_user))
    application.add_handler(CommandHandler("remove", remove_user))
    application.add_handler(CommandHandler("users", list_users))
    application.add_handler(CommandHandler("logout", logout_command))
    application.add_handler(CommandHandler("kill", cmd_kill))
    application.add_handler(CommandHandler("flush", flush))
    
    # Add callback handler for force join verification
    application.add_handler(CallbackQueryHandler(check_joined_callback, pattern="^check_joined$"))

    conv_login = ConversationHandler(
        entry_points=[CommandHandler("login", login_start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_login)

    conv_attack = ConversationHandler(
        entry_points=[CommandHandler("attack", attack_start)],
        states={
            SELECT_THREAD: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_thread)],
            NAMES: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_names)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_attack)
    
    # Broadcast conversation handler
    conv_broadcast = ConversationHandler(
        entry_points=[CommandHandler("broadcast", broadcast_start)],
        states={
            BROADCAST_MESSAGE: [
                MessageHandler(filters.TEXT | filters.PHOTO | filters.VIDEO | filters.DOCUMENT, broadcast_execute)
            ],
        },
        fallbacks=[CommandHandler("cancel", broadcast_cancel)],
    )
    application.add_handler(conv_broadcast)

    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, relay_input))

    print("🚀 Bot starting with task persistence, broadcast, and force join enabled!")
    print(f"👑 Owner: {OWNER_TG_ID}")
    print(f"📢 Required channels: {', '.join(REQUIRED_CHANNELS) if REQUIRED_CHANNELS and REQUIRED_CHANNELS != ['your_channel_1', 'your_channel_2'] else 'None configured'}")
    application.run_polling()

if __name__ == "__main__":
    main_bot()