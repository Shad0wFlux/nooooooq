import telebot
from telebot import types
import os
import time
import threading
import requests
from requests import post, get
from rich.console import Console
import concurrent.futures
import json

# Bot Configuration
BOT_TOKEN = "7470727246:AAHuF24HcdWfomigqsbJ9Z3BlLfMEukzB-Y"  # Replace with your bot token
bot = telebot.TeleBot(BOT_TOKEN)
console = Console()

# User state storage
user_states = {}
user_data = {}
session_cache = {}
active_reports = {}

# User state structure
class UserState:
    IDLE = 'idle'
    AWAITING_TARGET_ID = 'awaiting_target_id'
    AWAITING_REPORT_TYPE = 'awaiting_report_type'
    AWAITING_REPORTS_PER_SESSION = 'awaiting_reports_per_session'
    AWAITING_SLEEP_TIME = 'awaiting_sleep_time'
    REPORTING = 'reporting'

# Report types definition
report_options = {
    1: ("Spam", "Report spam content or behavior"),
    2: ("Self", "Report self-harm content"),
    3: ("Drugs", "Report drug-related content"),
    4: ("Nudity", "Report nudity content"),
    5: ("Violence", "Report violent content"),
    6: ("Hate", "Report hate speech"),
}

reason_ids = {
    "Spam": 1,
    "Self": 2,
    "Drugs": 3,
    "Nudity": 4,
    "Violence": 5,
    "Hate": 6,
}

def get_user_identifier(user):
    """Format user identifier as 'ID - Username'"""
    user_id = user.id
    username = user.username or "Unknown"
    return f"{user_id} - {username}"

def log_user_to_file(user_id, username):
    """Log user to users.txt file"""
    try:
        with open("users.txt", "a", encoding="utf-8") as f:
            f.write(f"{user_id} - {username}\n")
    except Exception as e:
        console.print(f"[red]Error logging user to file: {str(e)}[/red]")

def get_csrf_token(sessionid):
    try:
        if sessionid in session_cache:
            return session_cache[sessionid]
        
        r1 = get(
            "https://www.instagram.com/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
            },
            cookies={"sessionid": sessionid},
            timeout=10
        )
        if "csrftoken" in r1.cookies:
            session_cache[sessionid] = r1.cookies["csrftoken"]
            return r1.cookies["csrftoken"]
        else:
            return None
    except Exception as e:
        return None

def validate_session(sessionid):
    try:
        csrf = get_csrf_token(sessionid)
        if csrf:
            test_req = get(
                "https://www.instagram.com/accounts/edit/",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
                },
                cookies={"sessionid": sessionid},
                timeout=10,
                allow_redirects=False
            )
            return test_req.status_code == 200, csrf
        return False, None
    except Exception as e:
        return False, None

def filter_sessions(sessions, user_id, callback_message_id):
    valid_sessions = []
    invalid_sessions = []
    total = len(sessions)
    
    progress_message = bot.send_message(user_id, f"Checking sessions... (0/{total})")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_session = {executor.submit(validate_session, session): session for session in sessions}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_session):
            session = future_to_session[future]
            try:
                is_valid, csrf = future.result()
                if is_valid:
                    valid_sessions.append(session)
                    session_cache[session] = csrf
                else:
                    invalid_sessions.append(session)
            except Exception as e:
                invalid_sessions.append(session)
            
            completed += 1
            if completed % 5 == 0 or completed == total:
                try:
                    bot.edit_message_text(
                        f"Checking sessions... ({completed}/{total})",
                        user_id,
                        progress_message.message_id
                    )
                except:
                    pass
    
    result_message = (
        f"Found {len(valid_sessions)} valid sessions\n"
        f"Excluded {len(invalid_sessions)} invalid sessions"
    )
    
    try:
        bot.edit_message_text(result_message, user_id, progress_message.message_id)
    except:
        bot.send_message(user_id, result_message)
    
    return valid_sessions

def report_instagram(target_id, sessionid, csrftoken, reportType):
    try:
        r3 = post(
            f"https://i.instagram.com/users/{target_id}/flag/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
                "Host": "i.instagram.com",
                "cookie": f"sessionid={sessionid}",
                "X-CSRFToken": csrftoken,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            },
            data=f'source_name=&reason_id={reportType}&frx_context=',
            allow_redirects=False,
            timeout=15
        )
        # Check if status code is either 200 or 302
        return r3.status_code == 200 or r3.status_code == 302
    except Exception as e:
        return False

def start_reporting_process(user_id):
    target_id = user_data[user_id]['target_id']
    report_type = user_data[user_id]['report_type']
    reason_id = user_data[user_id]['reason_id']
    sleep_time = user_data[user_id]['sleep_time']
    valid_sessions = user_data[user_id]['valid_sessions']
    
    # Set reports_per_session conditionally
    reports_per_session = user_data[user_id].get('reports_per_session', float('inf'))
    if len(valid_sessions) == 1:
        reports_per_session = float('inf')  # Unlimited reports for single session
    
    # Create status message
    status_message = bot.send_message(
        user_id, 
        "Starting report process...", 
        parse_mode="HTML"
    )
    
    # Store active report info
    active_reports[user_id] = {
        'running': True,
        'status_message_id': status_message.message_id,
        'good_count': 0,
        'bad_count': 0,
        'invalid_sessions': [],
        'current_session_index': 0,
        'current_session': '',  # Store current session ID
    }
    
    # Start reporting in a separate thread
    threading.Thread(target=reporting_thread, args=(user_id, target_id, report_type, reason_id, sleep_time, reports_per_session, valid_sessions, status_message.message_id)).start()

def reporting_thread(user_id, target_id, report_type, reason_id, sleep_time, reports_per_session, valid_sessions, message_id):
    report_data = active_reports[user_id]
    good_count = 0
    bad_count = 0
    invalid_sessions = []
    multiple_sessions = len(valid_sessions) > 1
    last_update_time = time.time()
    update_interval = 2  # Update at least every 2 seconds
    current_session = ''
    
    try:
        while report_data['running'] and valid_sessions:
            for i, sessionid in enumerate(valid_sessions[:]):
                if sessionid in invalid_sessions:
                    continue
                
                report_data['current_session_index'] = i + 1
                report_data['current_session'] = sessionid
                current_session = sessionid
                
                csrftoken = get_csrf_token(sessionid)
                if not csrftoken:
                    bad_count += 1
                    invalid_sessions.append(sessionid)
                    if sessionid in valid_sessions:
                        valid_sessions.remove(sessionid)
                    
                    # Update message
                    if time.time() - last_update_time >= update_interval:
                        update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Session {sessionid[:8]}... is invalid and has been removed")
                        last_update_time = time.time()
                    continue

                session_success = 0
                
                # For single session continue indefinitely, otherwise use specified count
                report_counter = 0
                while (reports_per_session == float('inf') or report_counter < reports_per_session) and report_data['running']:
                    try:
                        if report_instagram(target_id, sessionid, csrftoken, reason_id):
                            good_count += 1
                            session_success += 1
                        else:
                            bad_count += 1
                            # Check if session is still valid
                            is_valid, _ = validate_session(sessionid)
                            if not is_valid:
                                invalid_sessions.append(sessionid)
                                if sessionid in valid_sessions:
                                    valid_sessions.remove(sessionid)
                                
                                # Update message
                                if time.time() - last_update_time >= update_interval:
                                    update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Session {sessionid[:8]}... has expired and has been removed")
                                    last_update_time = time.time()
                                break

                        # Update message
                        if time.time() - last_update_time >= update_interval:
                            update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions))
                            last_update_time = time.time()
                        
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                            
                        report_counter += 1
                        
                    except Exception as e:
                        bad_count += 1
                        break
                
                # Update message after each session
                if reports_per_session != float('inf'):  # Only show session progress for multiple sessions
                    update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Sent {session_success} reports from session {i+1}/{len(valid_sessions)}")
                else:
                    update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Sent {session_success} reports with single session")
                last_update_time = time.time()
            
            if not valid_sessions:
                update_status_message(user_id, good_count, bad_count, 0, 0, "No valid sessions remaining! Process stopped.")
                break
            
            # If multiple sessions, wait before starting a new cycle
            if multiple_sessions and report_data['running']:
                update_status_message(
                    user_id, 
                    good_count, 
                    bad_count, 
                    1, 
                    len(valid_sessions), 
                    "Completed full cycle. Starting new cycle..."
                )
                time.sleep(3)
        
        # Update final message
        report_data['good_count'] = good_count
        report_data['bad_count'] = bad_count
        
        # Show abbreviated session in final report
        session_display = current_session[:8] + "......" if current_session else "None"
        
        final_message = (
            f"<b>Final Report</b>\n\n"
            f"Successful reports: <b>{good_count}</b>\n"
            f"Failed reports: <b>{bad_count}</b>\n"
            f"Session: <b>{session_display}</b>\n"
            f"Wait time between reports: <b>{sleep_time} seconds</b>\n"
            f"Target ID: <b>{target_id}</b>\n"
            f"Report type: <b>{report_type}</b>\n\n"
            f"<b>Process completed!</b>"
        )
        
        try:
            bot.edit_message_text(
                final_message,
                user_id,
                message_id,
                parse_mode="HTML"
            )
        except:
            bot.send_message(user_id, final_message, parse_mode="HTML")
        
        # Reset state to idle
        user_states[user_id] = UserState.IDLE
        
    except Exception as e:
        error_message = f"Error during reporting process: {str(e)}"
        try:
            bot.edit_message_text(
                error_message,
                user_id,
                message_id
            )
        except:
            bot.send_message(user_id, error_message)
    
    finally:
        # Remove active data
        if user_id in active_reports:
            active_reports[user_id]['running'] = False
        # Clear user sessions to require re-upload
        if user_id in user_data and 'valid_sessions' in user_data[user_id]:
            del user_data[user_id]['valid_sessions']

def update_status_message(user_id, good_count, bad_count, current_session_idx, total_sessions, additional_info=None):
    if user_id not in active_reports:
        return
    
    report_data = active_reports[user_id]
    report_data['good_count'] = good_count
    report_data['bad_count'] = bad_count
    
    # Get current session for display
    current_session = report_data.get('current_session', '')
    session_display = current_session[:8] + "......" if current_session else "None"
    
    status_text = (
        f"<b>Report Status</b>\n\n"
        f"Successful reports: <b>{good_count}</b>\n"
        f"Failed reports: <b>{bad_count}</b>\n"
        f"Current session: <b>{session_display}</b>\n"
    )
    
    if total_sessions > 0:
        status_text += f"Session progress: <b>{current_session_idx}/{total_sessions}</b>\n"
    
    if additional_info:
        status_text += f"\n<i>{additional_info}</i>\n"
    
    status_text += "\n<i>You can stop the process anytime by sending /stop</i>"
    
    try:
        bot.edit_message_text(
            status_text,
            user_id,
            report_data['status_message_id'],
            parse_mode="HTML"
        )
    except:
        pass

# Basic bot commands
@bot.message_handler(commands=['start'])
def handle_start(message):
    user_id = message.from_user.id
    username = message.from_user.username or "Unknown"
    user_identifier = get_user_identifier(message.from_user)
    user_states[user_id] = UserState.IDLE
    
    # Log user with proper format and save to file
    console.print(f"[green]New user: {user_identifier}[/green]")
    log_user_to_file(user_id, username)
    
    welcome_message = (
        "Welcome to Instagram Report Bot\n\n"
        "Available commands:\n"
        "/report - Start reporting process\n"
        "/stop - Stop current reporting process\n"
        "/status - Check current report status\n"
        "/help - Show help information\n\n"
        "To begin, send your sessions.txt file or use the /report command"
    )
    
    bot.send_message(user_id, welcome_message)

@bot.message_handler(commands=['help'])
def handle_help(message):
    user_id = message.from_user.id
    help_message = (
        "<b>Help Guide</b>\n\n"
        "1. Send your sessions.txt file containing Instagram sessions\n"
        "2. Use /report to start reporting process\n"
        "3. Follow instructions to enter target ID and report type\n"
        "4. You can stop the process anytime using /stop\n\n"
        "<b>Available report types:</b>\n"
        "1 - Spam\n"
        "2 - Self Harm\n"
        "3 - Drugs\n"
        "4 - Nudity\n"
        "5 - Violence\n"
        "6 - Hate\n\n"
        "<b>Important notes:</b>\n"
        "â¢ Sessions are only used during the current reporting process and not stored\n"
        "â¢ You'll need to send your sessions.txt file for each new reporting process\n"
        "â¢ Don't use very short wait times to avoid bans\n"
        "â¢ Results are updated in real-time during reporting"
    )
    
    bot.send_message(user_id, help_message, parse_mode="HTML")

@bot.message_handler(commands=['report'])
def handle_report(message):
    user_id = message.from_user.id
    user_identifier = get_user_identifier(message.from_user)
    user_states[user_id] = UserState.AWAITING_TARGET_ID
    
    # Check if user has sessions in memory
    if user_id in user_data and 'valid_sessions' in user_data[user_id] and user_data[user_id]['valid_sessions']:
        valid_sessions = user_data[user_id]['valid_sessions']
        bot.send_message(
            user_id, 
            f"Found {len(valid_sessions)} sessions in memory.\n\nPlease enter target ID:"
        )
    else:
        bot.send_message(
            user_id, 
            "You must send a sessions file to start the reporting process!"
        )
        user_states[user_id] = UserState.IDLE

@bot.message_handler(commands=['stop'])
def handle_stop(message):
    user_id = message.from_user.id
    
    if user_id in active_reports and active_reports[user_id]['running']:
        active_reports[user_id]['running'] = False
        bot.send_message(user_id, "Reporting process stopped.")
        
        # Show final stats
        good_count = active_reports[user_id]['good_count']
        bad_count = active_reports[user_id]['bad_count']
        current_session = active_reports[user_id].get('current_session', '')
        session_display = current_session[:8] + "......" if current_session else "None"
        
        stats_message = (
            f"<b>Process Statistics</b>\n\n"
            f"Successful reports: <b>{good_count}</b>\n"
            f"Failed reports: <b>{bad_count}</b>\n"
            f"Session: <b>{session_display}</b>\n"
            f"Total: <b>{good_count + bad_count}</b>\n\n"
            f"<b>Process successfully stopped!</b>"
        )
        
        bot.send_message(user_id, stats_message, parse_mode="HTML")
        user_states[user_id] = UserState.IDLE
        
        # Clear user sessions to require re-upload
        if user_id in user_data and 'valid_sessions' in user_data[user_id]:
            del user_data[user_id]['valid_sessions']
    else:
        bot.send_message(user_id, "No active reporting process.")

@bot.message_handler(commands=['status'])
def handle_status(message):
    user_id = message.from_user.id
    
    if user_id in active_reports and active_reports[user_id]['running']:
        good_count = active_reports[user_id]['good_count']
        bad_count = active_reports[user_id]['bad_count']
        current_session = active_reports[user_id].get('current_session', '')
        session_display = current_session[:8] + "......" if current_session else "None"
        
        status_message = (
            f"<b>Current Process Status</b>\n\n"
            f"Successful reports: <b>{good_count}</b>\n"
            f"Failed reports: <b>{bad_count}</b>\n"
            f"Current session: <b>{session_display}</b>\n"
            f"Total: <b>{good_count + bad_count}</b>\n\n"
            f"<i>Process is running... You can stop it using /stop</i>"
        )
        
        bot.send_message(user_id, status_message, parse_mode="HTML")
    else:
        bot.send_message(user_id, "No active reporting process.")

# Handle files (sessions.txt)
@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    username = message.from_user.username or "Unknown"
    user_identifier = get_user_identifier(message.from_user)
    
    # Check file type
    if message.document.file_name.lower() != 'sessions.txt':
        bot.send_message(user_id, "Please send a file named sessions.txt only.")
        return
    
    # Log user activity
    console.print(f"[yellow]User {user_identifier} uploaded sessions file[/yellow]")
    log_user_to_file(user_id, username)
    
    # Download file
    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)
    
    # Process the sessions in memory, not saving to disk
    sessions = downloaded_file.decode('utf-8').splitlines()
    
    if not sessions:
        bot.send_message(user_id, "The sessions file is empty! Please send a valid file.")
        return
    
    # Store in user_data temporarily
    if user_id not in user_data:
        user_data[user_id] = {}
    
    # Check sessions
    bot.send_message(user_id, "Checking sessions... This may take some time.")
    valid_sessions = filter_sessions(sessions, user_id, 0)
    
    if not valid_sessions:
        bot.send_message(user_id, "No valid sessions found! Please check your sessions file.")
        return
    
    user_data[user_id]['valid_sessions'] = valid_sessions
    bot.send_message(user_id, f"Found {len(valid_sessions)} valid sessions.\nUse /report to start reporting process.")

# Handle text messages
@bot.message_handler(func=lambda message: True)
def handle_messages(message):
    user_id = message.from_user.id
    text = message.text.strip()
    
    # Ensure user has a state
    if user_id not in user_states:
        user_states[user_id] = UserState.IDLE
    
    state = user_states[user_id]
    
    # Process messages based on user state
    if state == UserState.AWAITING_TARGET_ID:
        # Validate target ID
        if not text.isdigit():
            bot.send_message(user_id, "Target ID must be a number only. Please enter a valid ID:")
            return
            
        # Save target ID
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['target_id'] = text
        
        # Create keyboard for report types
        markup = types.InlineKeyboardMarkup()
        for key, (value, desc) in report_options.items():
            button_text = f"{key}. {value} - {desc}"
            markup.add(types.InlineKeyboardButton(button_text, callback_data=f"report_type_{key}"))
        
        bot.send_message(
            user_id, 
            "Select report type:", 
            reply_markup=markup
        )
        
        user_states[user_id] = UserState.AWAITING_REPORT_TYPE
        
    elif state == UserState.AWAITING_REPORTS_PER_SESSION:
        # Validate reports per session
        if not text.isdigit() or int(text) <= 0:
            bot.send_message(user_id, "Please enter a positive number. Enter a valid number:")
            return
            
        # Save reports per session
        user_data[user_id]['reports_per_session'] = int(text)
        
        bot.send_message(user_id, "Enter wait time between reports (in seconds):")
        user_states[user_id] = UserState.AWAITING_SLEEP_TIME
        
    elif state == UserState.AWAITING_SLEEP_TIME:
        # Validate wait time
        try:
            sleep_time = float(text)
            if sleep_time < 0:
                bot.send_message(user_id, "Please enter a positive number. Enter a valid time:")
                return
        except ValueError:
            bot.send_message(user_id, "Please enter a valid number or decimal. Enter a valid time:")
            return
            
        # Save wait time
        user_data[user_id]['sleep_time'] = sleep_time
        
        # Show settings summary
        target_id = user_data[user_id]['target_id']
        report_type = user_data[user_id]['report_type']
        valid_sessions = user_data[user_id]['valid_sessions']
        
        # Only show reports_per_session in summary if multiple sessions
        summary = (
            f"<b>Settings Summary</b>\n\n"
            f"Target ID: <b>{target_id}</b>\n"
            f"Report Type: <b>{report_type}</b>\n"
        )
        
        # Only add reports_per_session to summary if multiple sessions
        if len(valid_sessions) > 1 and 'reports_per_session' in user_data[user_id]:
            reports_per_session = user_data[user_id]['reports_per_session']
            summary += f"Reports per session: <b>{reports_per_session}</b>\n"
        
        summary += (
            f"Wait time between reports: <b>{sleep_time} seconds</b>\n"
            f"Available sessions: <b>{len(valid_sessions)}</b>\n\n"
            f"Do you want to start the reporting process?"
        )
        
        # Create confirmation buttons
        markup = types.InlineKeyboardMarkup()
        markup.row(
            types.InlineKeyboardButton("Start", callback_data="start_report"),
            types.InlineKeyboardButton("Cancel", callback_data="cancel_report")
        )
        
        bot.send_message(user_id, summary, reply_markup=markup, parse_mode="HTML")
        user_states[user_id] = UserState.REPORTING

# Handle button responses
@bot.callback_query_handler(func=lambda call: True)
def handle_callback_query(call):
    user_id = call.from_user.id
    
    # Handle report type selection
    if call.data.startswith("report_type_"):
        report_type_id = int(call.data.split("_")[-1])
        report_type, description = report_options[report_type_id]
        
        # Save report type
        user_data[user_id]['report_type'] = report_type
        user_data[user_id]['reason_id'] = reason_ids[report_type]
        
        # Inform user
        bot.answer_callback_query(call.id, f"Selected: {report_type}")
        bot.edit_message_text(
            f"Selected report type: <b>{report_type}</b> - {description}",
            user_id,
            call.message.message_id,
            parse_mode="HTML"
        )
        
        # Check if there's only one session - skip asking for reports per session
        valid_sessions = user_data[user_id]['valid_sessions']
        if len(valid_sessions) == 1:
            # Skip asking for reports per session if only one session
            # Don't set any value - we'll use infinite reports for single session
            bot.send_message(user_id, "Enter wait time between reports (in seconds):")
            user_states[user_id] = UserState.AWAITING_SLEEP_TIME
        else:
            # Ask for reports per session only if multiple sessions
            bot.send_message(user_id, "Enter reports per session:")
            user_states[user_id] = UserState.AWAITING_REPORTS_PER_SESSION
    
    # Start reporting process
    elif call.data == "start_report":
        bot.answer_callback_query(call.id, "Starting process...")
        bot.edit_message_text(
            "Starting reporting process...",
            user_id,
            call.message.message_id
        )
        
        start_reporting_process(user_id)
    
    # Cancel reporting process
    elif call.data == "cancel_report":
        bot.answer_callback_query(call.id, "Process canceled")
        bot.edit_message_text(
            "Reporting process canceled.",
            user_id,
            call.message.message_id
        )
        
        user_states[user_id] = UserState.IDLE
        # Clear sessions on cancel too
        if user_id in user_data and 'valid_sessions' in user_data[user_id]:
            del user_data[user_id]['valid_sessions']

# Run the bot
if __name__ == "__main__":
    # Create necessary users directory for logs only
    os.makedirs("users", exist_ok=True)
    
    # Create blank users.txt file if it doesn't exist
    if not os.path.exists("users.txt"):
        with open("users.txt", "w") as f:
            pass
    
    console.print("[bold green]Bot started successfully![/bold green]")
    console.print("[yellow]Waiting for messages...[/yellow]")
    
    # Start the bot
    bot.polling(none_stop=True)