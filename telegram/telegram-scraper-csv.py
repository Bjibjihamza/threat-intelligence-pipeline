import os
import json
import csv
import asyncio
import time
import sys
import uuid
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from pathlib import Path
from io import StringIO
from telethon import TelegramClient
from telethon.tl.types import MessageMediaPhoto, MessageMediaDocument, MessageMediaWebPage, User, PeerChannel
from telethon.errors import FloodWaitError, SessionPasswordNeededError
import qrcode

warnings.filterwarnings("ignore", message="Using async sessions support is an experimental feature")

def display_ascii_art():
    WHITE = "\033[97m"
    RESET = "\033[0m"
    art = r"""
___________________  _________
\__    ___/  _____/ /   _____/
  |    | /   \  ___ \_____  \ 
  |    | \    \_\  \/        \
  |____|  \______  /_______  /
                 \/        \/
    """
    print(WHITE + art + RESET)

@dataclass
class MessageData:
    message_id: int
    date: str
    sender_id: int
    first_name: Optional[str]
    last_name: Optional[str]
    username: Optional[str]
    message: str
    media_type: Optional[str]
    media_path: Optional[str]
    reply_to: Optional[int]

class OptimizedTelegramScraper:
    def __init__(self):
        self.STATE_FILE = 'state.json'
        self.state = self.load_state()
        self.client = None
        self.continuous_scraping_active = False
        self.max_concurrent_downloads = 5
        self.batch_size = 100
        self.state_save_interval = 50
        
    def load_state(self) -> Dict[str, Any]:
        if os.path.exists(self.STATE_FILE):
            try:
                with open(self.STATE_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            'api_id': None,
            'api_hash': None,
            'channels': {},
            'scrape_media': True,
        }

    def save_state(self):
        try:
            with open(self.STATE_FILE, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            print(f"Failed to save state: {e}")

    def get_csv_path(self, channel: str) -> Path:
        channel_dir = Path(channel)
        channel_dir.mkdir(exist_ok=True)
        return channel_dir / f'{channel}.csv'

    def ensure_csv_header(self, csv_path: Path):
        if not csv_path.exists():
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'message_id', 'date', 'sender_id', 'first_name', 'last_name', 'username', 
                                'message', 'media_type', 'media_path', 'reply_to'])

    def batch_append_messages(self, channel: str, messages: List[MessageData]):
        if not messages:
            return
            
        csv_path = self.get_csv_path(channel)
        self.ensure_csv_header(csv_path)
        
        with open(csv_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for msg in messages:
                writer.writerow([None, msg.message_id, msg.date, msg.sender_id, msg.first_name, 
                                msg.last_name, msg.username, msg.message, msg.media_type, 
                                msg.media_path, msg.reply_to])

    def update_media_path_in_csv(self, channel: str, message_id: int, media_path: str):
        csv_path = self.get_csv_path(channel)
        if not csv_path.exists():
            return

        rows = []
        updated = False
        with open(csv_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if int(row['message_id']) == message_id and (not row['media_path'] or row['media_path'] == ''):
                    row['media_path'] = media_path
                    updated = True
                rows.append(row)

        if updated:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['id', 'message_id', 'date', 'sender_id', 'first_name', 'last_name', 'username', 
                              'message', 'media_type', 'media_path', 'reply_to']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

    def read_csv_data(self, channel: str) -> List[Dict[str, Any]]:
        csv_path = self.get_csv_path(channel)
        if not csv_path.exists():
            return []
        with open(csv_path, 'r', newline='', encoding='utf-8') as f:
            return list(csv.DictReader(f))

    def get_message_count(self, channel: str) -> int:
        data = self.read_csv_data(channel)
        return len(data)

    def get_messages_with_media_no_path(self, channel: str) -> List[int]:
        data = self.read_csv_data(channel)
        return [int(row['message_id']) for row in data if row['media_type'] and row['media_type'] != 'MessageMediaWebPage' and (not row['media_path'] or row['media_path'] == '')]

    def get_media_stats(self, channel: str) -> tuple[int, int]:
        data = self.read_csv_data(channel)
        total_with_media = sum(1 for row in data if row['media_type'] and row['media_type'] != 'MessageMediaWebPage')
        total_with_files = sum(1 for row in data if row['media_type'] and row['media_type'] != 'MessageMediaWebPage' and row['media_path'] and row['media_path'] != '')
        return total_with_media, total_with_files

    async def download_media(self, channel: str, message) -> Optional[str]:
        if not message.media or not self.state['scrape_media']:
            return None

        if isinstance(message.media, MessageMediaWebPage):
            return None

        try:
            channel_dir = Path(channel)
            media_folder = channel_dir / 'media'
            media_folder.mkdir(exist_ok=True)
            
            if isinstance(message.media, MessageMediaPhoto):
                original_name = getattr(message.file, 'name', None) or "photo.jpg"
                ext = "jpg"
            elif isinstance(message.media, MessageMediaDocument):
                ext = getattr(message.file, 'ext', 'bin') if message.file else 'bin'
                original_name = getattr(message.file, 'name', None) or f"document.{ext}"
            else:
                return None
            
            base_name = Path(original_name).stem
            extension = Path(original_name).suffix or f".{ext}"
            unique_filename = f"{message.id}-{base_name}{extension}"
            media_path = media_folder / unique_filename
            
            existing_files = list(media_folder.glob(f"{message.id}-*"))
            if existing_files:
                return str(existing_files[0])

            for attempt in range(3):
                try:
                    downloaded_path = await message.download_media(file=str(media_path))
                    if downloaded_path and Path(downloaded_path).exists():
                        return downloaded_path
                    else:
                        return None
                except FloodWaitError as e:
                    if attempt < 2:
                        await asyncio.sleep(e.seconds)
                    else:
                        return None
                except Exception:
                    if attempt < 2:
                        await asyncio.sleep(2 ** attempt)
                    else:
                        return None
            
            return None
        except Exception:
            return None

    async def update_media_path(self, channel: str, message_id: int, media_path: str):
        self.update_media_path_in_csv(channel, message_id, media_path)

    async def scrape_channel(self, channel: str, offset_id: int):
        try:
            entity = await self.client.get_entity(PeerChannel(int(channel)) if channel.startswith('-') else channel)
            result = await self.client.get_messages(entity, offset_id=offset_id, reverse=True, limit=0)
            total_messages = result.total

            if total_messages == 0:
                print(f"No messages found in channel {channel}")
                return

            print(f"Found {total_messages} messages in channel {channel}")

            message_batch = []
            media_tasks = []
            processed_messages = 0
            last_message_id = offset_id
            semaphore = asyncio.Semaphore(self.max_concurrent_downloads)

            async for message in self.client.iter_messages(entity, offset_id=offset_id, reverse=True):
                try:
                    sender = await message.get_sender()
                    
                    msg_data = MessageData(
                        message_id=message.id,
                        date=message.date.strftime('%Y-%m-%d %H:%M:%S'),
                        sender_id=message.sender_id,
                        first_name=getattr(sender, 'first_name', None) if isinstance(sender, User) else None,
                        last_name=getattr(sender, 'last_name', None) if isinstance(sender, User) else None,
                        username=getattr(sender, 'username', None) if isinstance(sender, User) else None,
                        message=message.message or '',
                        media_type=message.media.__class__.__name__ if message.media else None,
                        media_path=None,
                        reply_to=message.reply_to_msg_id if message.reply_to else None
                    )
                    
                    message_batch.append(msg_data)

                    if self.state['scrape_media'] and message.media and not isinstance(message.media, MessageMediaWebPage):
                        media_tasks.append(message)

                    last_message_id = message.id
                    processed_messages += 1

                    if len(message_batch) >= self.batch_size:
                        self.batch_append_messages(channel, message_batch)
                        message_batch.clear()

                    if processed_messages % self.state_save_interval == 0:
                        self.state['channels'][channel] = last_message_id
                        self.save_state()

                    progress = (processed_messages / total_messages) * 100
                    bar_length = 30
                    filled_length = int(bar_length * processed_messages // total_messages)
                    bar = '█' * filled_length + '░' * (bar_length - filled_length)
                    
                    sys.stdout.write(f"\r📄 Messages: [{bar}] {progress:.1f}% ({processed_messages}/{total_messages})")
                    sys.stdout.flush()

                except Exception as e:
                    print(f"\nError processing message {message.id}: {e}")

            if message_batch:
                self.batch_append_messages(channel, message_batch)

            if media_tasks:
                total_media = len(media_tasks)
                completed_media = 0
                successful_downloads = 0
                print(f"\n📥 Downloading {total_media} media files...")
                
                semaphore = asyncio.Semaphore(self.max_concurrent_downloads)
                
                async def download_single_media(message):
                    async with semaphore:
                        return await self.download_media(channel, message)
                
                batch_size = 10
                for i in range(0, len(media_tasks), batch_size):
                    batch = media_tasks[i:i + batch_size]
                    tasks = [asyncio.create_task(download_single_media(msg)) for msg in batch]
                    
                    for j, task in enumerate(tasks):
                        try:
                            media_path = await task
                            if media_path:
                                await self.update_media_path(channel, batch[j].id, media_path)
                                successful_downloads += 1
                        except Exception:
                            pass
                        
                        completed_media += 1
                        progress = (completed_media / total_media) * 100
                        bar_length = 30
                        filled_length = int(bar_length * completed_media // total_media)
                        bar = '█' * filled_length + '░' * (bar_length - filled_length)
                        
                        sys.stdout.write(f"\r📥 Media: [{bar}] {progress:.1f}% ({completed_media}/{total_media})")
                        sys.stdout.flush()
                
                print(f"\n✅ Media download complete! ({successful_downloads}/{total_media} successful)")

            self.state['channels'][channel] = last_message_id
            self.save_state()
            print(f"\nCompleted scraping channel {channel}")

        except Exception as e:
            print(f"Error with channel {channel}: {e}")

    async def rescrape_media(self, channel: str):
        message_ids = self.get_messages_with_media_no_path(channel)

        if not message_ids:
            print(f"No media files to reprocess for channel {channel}")
            return

        print(f"📥 Reprocessing {len(message_ids)} media files for channel {channel}")

        try:
            entity = await self.client.get_entity(PeerChannel(int(channel)) if channel.startswith('-') else channel)
            semaphore = asyncio.Semaphore(self.max_concurrent_downloads)
            completed_media = 0
            successful_downloads = 0
            
            async def download_single_media(message):
                async with semaphore:
                    return await self.download_media(channel, message)

            batch_size = 10
            for i in range(0, len(message_ids), batch_size):
                batch_ids = message_ids[i:i + batch_size]
                messages = await self.client.get_messages(entity, ids=batch_ids)
                
                valid_messages = [msg for msg in messages if msg and msg.media and not isinstance(msg.media, MessageMediaWebPage)]
                tasks = [asyncio.create_task(download_single_media(msg)) for msg in valid_messages]

                for j, task in enumerate(tasks):
                    try:
                        media_path = await task
                        if media_path:
                            await self.update_media_path(channel, valid_messages[j].id, media_path)
                            successful_downloads += 1
                    except Exception:
                        pass
                    
                    completed_media += 1
                    progress = (completed_media / len(message_ids)) * 100
                    bar_length = 30
                    filled_length = int(bar_length * completed_media // len(message_ids))
                    bar = '█' * filled_length + '░' * (bar_length - filled_length)
                    
                    sys.stdout.write(f"\r🔄 Rescrape: [{bar}] {progress:.1f}% ({completed_media}/{len(message_ids)})")
                    sys.stdout.flush()

            print(f"\n✅ Media reprocessing complete! ({successful_downloads}/{len(message_ids)} successful)")

        except Exception as e:
            print(f"Error reprocessing media: {e}")

    async def fix_missing_media(self, channel: str):
        total_with_media, total_with_files = self.get_media_stats(channel)
        missing_count = total_with_media - total_with_files
        
        print(f"\n📊 Media Analysis for {channel}:")
        print(f"Messages with media: {total_with_media}")
        print(f"Media files downloaded: {total_with_files}")
        print(f"Missing media files: {missing_count}")
        
        if missing_count == 0:
            print("✅ All media files are already downloaded!")
            return

        missing_media = self.get_messages_with_media_no_path(channel)
        
        if not missing_media:
            print("✅ No missing media found!")
            return

        print(f"\n🔧 Attempting to download {len(missing_media)} missing media files...")
        
        try:
            entity = await self.client.get_entity(PeerChannel(int(channel)) if channel.startswith('-') else channel)
            semaphore = asyncio.Semaphore(self.max_concurrent_downloads)
            completed_media = 0
            successful_downloads = 0
            
            async def download_single_media(message):
                async with semaphore:
                    return await self.download_media(channel, message)
            
            batch_size = 10
            for i in range(0, len(missing_media), batch_size):
                batch = missing_media[i:i + batch_size]
                message_ids = batch
                
                messages = await self.client.get_messages(entity, ids=message_ids)
                valid_messages = [msg for msg in messages if msg and msg.media and not isinstance(msg.media, MessageMediaWebPage)]
                
                tasks = [asyncio.create_task(download_single_media(msg)) for msg in valid_messages]

                for j, task in enumerate(tasks):
                    try:
                        media_path = await task
                        if media_path:
                            await self.update_media_path(channel, valid_messages[j].id, media_path)
                            successful_downloads += 1
                    except Exception:
                        pass
                    
                    completed_media += 1
                    progress = (completed_media / len(missing_media)) * 100
                    bar_length = 30
                    filled_length = int(bar_length * completed_media // len(missing_media))
                    bar = '█' * filled_length + '░' * (bar_length - filled_length)
                    
                    sys.stdout.write(f"\r🔧 Fix Media: [{bar}] {progress:.1f}% ({completed_media}/{len(missing_media)})")
                    sys.stdout.flush()

            print(f"\n✅ Media fix complete! ({successful_downloads}/{len(missing_media)} successful)")

        except Exception as e:
            print(f"Error fixing missing media: {e}")

    async def continuous_scraping(self):
        self.continuous_scraping_active = True
        
        try:
            while self.continuous_scraping_active:
                start_time = time.time()
                
                for channel in self.state['channels']:
                    if not self.continuous_scraping_active:
                        break
                    print(f"\nChecking for new messages in channel: {channel}")
                    await self.scrape_channel(channel, self.state['channels'][channel])
                
                elapsed = time.time() - start_time
                sleep_time = max(0, 60 - elapsed)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    
        except asyncio.CancelledError:
            print("Continuous scraping stopped")
        finally:
            self.continuous_scraping_active = False

    def export_to_csv(self, channel: str):
        csv_path = self.get_csv_path(channel)
        if csv_path.exists():
            print(f"CSV already exists at {csv_path}")
        else:
            print("No CSV to export")

    def export_to_json(self, channel: str):
        data = self.read_csv_data(channel)
        if not data:
            print("No data to export")
            return

        json_file = Path(channel) / f'{channel}.json'
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Exported {len(data)} messages to {json_file}")

    async def export_data(self):
        if not self.state['channels']:
            print("No channels to export")
            return
            
        for channel in self.state['channels']:
            print(f"Exporting data for channel {channel}...")
            try:
                self.export_to_csv(channel)
                self.export_to_json(channel)
                print(f"✅ Completed export for channel {channel}")
            except Exception as e:
                print(f"❌ Export failed for channel {channel}: {e}")

    async def view_channels(self):
        if not self.state['channels']:
            print("No channels saved")
            return
        
        print("\nCurrent channels:")
        for i, (channel, last_id) in enumerate(self.state['channels'].items(), 1):
            try:
                count = self.get_message_count(channel)
                print(f"[{i}] Channel ID: {channel}, Last Message ID: {last_id}, Messages: {count}")
            except:
                print(f"[{i}] Channel ID: {channel}, Last Message ID: {last_id}")

    async def list_channels(self):
        try:
            print("\nList of channels joined by account:")
            count = 1
            async for dialog in self.client.iter_dialogs():
                if dialog.id != 777000:
                    print(f"[{count}] {dialog.title} (id: {dialog.id})")
                    count += 1
        except Exception as e:
            print(f"Error listing channels: {e}")

    def display_qr_code_ascii(self, qr_login):
        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(qr_login.url)
        qr.make()
        
        f = StringIO()
        qr.print_ascii(out=f)
        f.seek(0)
        print(f.read())

    async def qr_code_auth(self):
        print("\nChoosing QR Code authentication...")
        print("Please scan the QR code with your Telegram app:")
        print("1. Open Telegram on your phone")
        print("2. Go to Settings > Devices > Scan QR")
        print("3. Scan the code below\n")
        
        qr_login = await self.client.qr_login()
        self.display_qr_code_ascii(qr_login)
        
        try:
            await qr_login.wait()
            print("\n✅ Successfully logged in via QR code!")
            return True
        except SessionPasswordNeededError:
            password = input("Two-factor authentication enabled. Enter your password: ")
            await self.client.sign_in(password=password)
            print("\n✅ Successfully logged in with 2FA!")
            return True
        except Exception as e:
            print(f"\n❌ QR code authentication failed: {e}")
            return False

    async def phone_auth(self):
        phone = input("Enter your phone number: ")
        await self.client.send_code_request(phone)
        code = input("Enter the code you received: ")
        
        try:
            await self.client.sign_in(phone, code)
            print("\n✅ Successfully logged in via phone!")
            return True
        except SessionPasswordNeededError:
            password = input("Two-factor authentication enabled. Enter your password: ")
            await self.client.sign_in(password=password)
            print("\n✅ Successfully logged in with 2FA!")
            return True
        except Exception as e:
            print(f"\n❌ Phone authentication failed: {e}")
            return False

    async def initialize_client(self):
        if not all([self.state.get('api_id'), self.state.get('api_hash')]):
            print("\n=== API Configuration Required ===")
            print("You need to provide API credentials from https://my.telegram.org")
            try:
                self.state['api_id'] = int(input("Enter your API ID: "))
                self.state['api_hash'] = input("Enter your API Hash: ")
                self.save_state()
            except ValueError:
                print("Invalid API ID. Must be a number.")
                return False

        self.client = TelegramClient('session', self.state['api_id'], self.state['api_hash'])
        
        try:
            await self.client.connect()
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False
        
        if not await self.client.is_user_authorized():
            print("\n=== Choose Authentication Method ===")
            print("[1] QR Code (Recommended - No phone number needed)")
            print("[2] Phone Number (Traditional method)")
            
            while True:
                choice = input("Enter your choice (1 or 2): ").strip()
                if choice in ['1', '2']:
                    break
                print("Please enter 1 or 2")
            
            success = await self.qr_code_auth() if choice == '1' else await self.phone_auth()
                
            if not success:
                print("Authentication failed. Please try again.")
                await self.client.disconnect()
                return False
        else:
            print("✅ Already authenticated!")
            
        return True

    def parse_channel_selection(self, choice):
        channels_list = list(self.state['channels'].keys())
        selected_channels = []
        
        if choice.lower() == 'all':
            return channels_list
        
        for selection in [x.strip() for x in choice.split(',')]:
            try:
                if selection.startswith('-'):
                    if selection in self.state['channels']:
                        selected_channels.append(selection)
                    else:
                        print(f"Channel ID {selection} not found in your channels")
                else:
                    num = int(selection)
                    if 1 <= num <= len(channels_list):
                        selected_channels.append(channels_list[num - 1])
                    else:
                        print(f"Invalid channel number: {num}. Valid range: 1-{len(channels_list)}")
            except ValueError:
                print(f"Invalid input: {selection}. Use numbers (1,2,3) or full IDs (-100123...)")
        
        return selected_channels

    async def scrape_specific_channels(self):
        if not self.state['channels']:
            print("No channels available. Use [L] to add channels first")
            return

        await self.view_channels()
        print("\n📥 Scrape Options:")
        print("• Single: 1 or -1001234567890")
        print("• Multiple: 1,3,5 or mix formats")
        print("• All channels: all")
        
        choice = input("\nEnter selection: ").strip()
        selected_channels = self.parse_channel_selection(choice)
        
        if selected_channels:
            print(f"\n🚀 Starting scrape of {len(selected_channels)} channel(s)...")
            for i, channel in enumerate(selected_channels, 1):
                print(f"\n[{i}/{len(selected_channels)}] Scraping: {channel}")
                await self.scrape_channel(channel, self.state['channels'][channel])
            print(f"\n✅ Completed scraping {len(selected_channels)} channel(s)!")
        else:
            print("❌ No valid channels selected")

    async def manage_channels(self):
        while True:
            print("\n" + "="*40)
            print("           TELEGRAM SCRAPER")
            print("="*40)
            print("[S] Scrape channels")
            print("[C] Continuous scraping")
            print(f"[M] Media scraping: {'ON' if self.state['scrape_media'] else 'OFF'}")
            print("[L] List & add channels")
            print("[R] Remove channels")
            print("[E] Export data")
            print("[T] Rescrape media")
            print("[F] Fix missing media")
            print("[Q] Quit")
            print("="*40)

            choice = input("Enter your choice: ").lower().strip()
            
            try:
                if choice == 'r':
                    if not self.state['channels']:
                        print("No channels to remove")
                        continue
                        
                    await self.view_channels()
                    print("\nTo remove channels:")
                    print("• Single: 1 or -1001234567890")
                    print("• Multiple: 1,2,3 or mix formats")
                    selection = input("Enter selection: ").strip()
                    selected_channels = self.parse_channel_selection(selection)
                    
                    if selected_channels:
                        removed_count = 0
                        for channel in selected_channels:
                            if channel in self.state['channels']:
                                del self.state['channels'][channel]
                                print(f"✅ Removed channel {channel}")
                                removed_count += 1
                            else:
                                print(f"❌ Channel {channel} not found")
                        
                        if removed_count > 0:
                            self.save_state()
                            print(f"\n🎉 Removed {removed_count} channel(s)!")
                            await self.view_channels()
                        else:
                            print("No channels were removed")
                    else:
                        print("No valid channels selected")
                        
                elif choice == 's':
                    await self.scrape_specific_channels()
                    
                elif choice == 'm':
                    self.state['scrape_media'] = not self.state['scrape_media']
                    self.save_state()
                    print(f"\n✅ Media scraping {'enabled' if self.state['scrape_media'] else 'disabled'}")
                    
                elif choice == 'c':
                    task = asyncio.create_task(self.continuous_scraping())
                    print("Continuous scraping started. Press Ctrl+C to stop.")
                    try:
                        await asyncio.sleep(float('inf'))
                    except KeyboardInterrupt:
                        self.continuous_scraping_active = False
                        task.cancel()
                        print("\nStopping continuous scraping...")
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                            
                elif choice == 'e':
                    await self.export_data()
                    
                elif choice == 'l':
                    channels_list = []
                    async for dialog in self.client.iter_dialogs():
                        if dialog.id != 777000:
                            channels_list.append(str(dialog.id))
                    
                    await self.list_channels()
                    print("\nTo add channels from the list above:")
                    print("• Single: 1 or -1001234567890")
                    print("• Multiple: 1,3,5 or mix formats")
                    print("• Press Enter to skip adding")
                    selection = input("\nEnter selection (or Enter to skip): ").strip()
                    
                    if selection:
                        added_count = 0
                        for sel in [x.strip() for x in selection.split(',')]:
                            try:
                                if sel.startswith('-'):
                                    channel = sel
                                else:
                                    num = int(sel)
                                    if 1 <= num <= len(channels_list):
                                        channel = channels_list[num - 1]
                                    else:
                                        print(f"Invalid number: {num}. Choose 1-{len(channels_list)}")
                                        continue
                                
                                if channel in self.state['channels']:
                                    print(f"Channel {channel} already added")
                                else:
                                    self.state['channels'][channel] = 0
                                    self.save_state()
                                    print(f"✅ Added channel {channel}")
                                    added_count += 1
                                    
                            except ValueError:
                                print(f"Invalid input: {sel}")
                        
                        if added_count > 0:
                            print(f"\n🎉 Added {added_count} new channel(s)!")
                            await self.view_channels()
                        else:
                            print("No new channels were added")
                    
                elif choice == 't':
                    if not self.state['channels']:
                        print("No channels available. Add channels first")
                        continue
                        
                    await self.view_channels()
                    print("\nEnter channel NUMBER (1,2,3...) or full channel ID (-100123...)")
                    selection = input("Enter your selection: ").strip()
                    selected_channels = self.parse_channel_selection(selection)
                    
                    if len(selected_channels) == 1:
                        channel = selected_channels[0]
                        print(f"Rescaping media for channel: {channel}")
                        await self.rescrape_media(channel)
                    elif len(selected_channels) > 1:
                        print("Please select only one channel for media rescaping")
                    else:
                        print("No valid channel selected")
                    
                elif choice == 'f':
                    if not self.state['channels']:
                        print("No channels available. Add channels first")
                        continue
                        
                    await self.view_channels()
                    print("\nEnter channel NUMBER (1,2,3...) or full channel ID (-100123...)")
                    selection = input("Enter your selection: ").strip()
                    selected_channels = self.parse_channel_selection(selection)
                    
                    if len(selected_channels) == 1:
                        channel = selected_channels[0]
                        await self.fix_missing_media(channel)
                    elif len(selected_channels) > 1:
                        print("Please select only one channel for fixing missing media")
                    else:
                        print("No valid channel selected")
                    
                elif choice == 'q':
                    print("\n👋 Goodbye!")
                    if self.client:
                        await self.client.disconnect()
                    sys.exit()
                    
                else:
                    print("Invalid option")
                    
            except Exception as e:
                print(f"Error: {e}")

    async def run(self):
        display_ascii_art()
        if await self.initialize_client():
            try:
                await self.manage_channels()
            finally:
                if self.client:
                    await self.client.disconnect()
        else:
            print("Failed to initialize client. Exiting.")

async def main():
    scraper = OptimizedTelegramScraper()
    await scraper.run()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
        sys.exit()