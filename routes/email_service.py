import smtplib
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from .config import settings
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.smtp_server = settings.EMAIL_HOST
        self.smtp_port = settings.EMAIL_PORT
        self.email_username = settings.EMAIL_USERNAME
        self.email_password = settings.EMAIL_APP_PASSWORD
        self.from_email = settings.EMAIL_FROM
        self.from_name = settings.EMAIL_FROM_NAME

    def generate_otp(self, length: int = 6) -> str:
        """Generate a random OTP code"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))

    def generate_reset_token(self, length: int = 32) -> str:
        """Generate a secure password reset token"""
        return secrets.token_urlsafe(length)

    def test_email_connection(self) -> bool:
        """Test email connection and configuration"""
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_username, self.email_password)
            logger.info("Email connection test successful")
            return True
        except Exception as e:
            logger.error(f"Email connection test failed: {str(e)}")
            return False

    def send_verification_email(self, to_email: str, username: str, otp_code: str) -> bool:
        """Send OTP verification email"""
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Verify Your Email Address - OTP Code"
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email

            # Create HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Email Verification</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                    .otp-code {{ background: #667eea; color: white; padding: 20px; font-size: 32px; font-weight: bold; text-align: center; border-radius: 8px; letter-spacing: 5px; margin: 20px 0; }}
                    .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 30px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Email Verification</h1>
                        <p>Welcome to our platform!</p>
                    </div>
                    <div class="content">
                        <h2>Hello {username}!</h2>
                        <p>Thank you for signing up! To complete your registration, please verify your email address using the OTP code below:</p>
                        
                        <div class="otp-code">{otp_code}</div>
                        
                        <div class="warning">
                            <strong>⚠️ Important:</strong>
                            <ul>
                                <li>This code will expire in <strong>10 minutes</strong></li>
                                <li>Never share this code with anyone</li>
                                <li>If you didn't request this, please ignore this email</li>
                            </ul>
                        </div>
                        
                        <p>Enter this code on the verification page to activate your account.</p>
                        
                        <p>If you have any questions, feel free to contact our support team.</p>
                        
                        <p>Best regards,<br>The Team</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated message. Please do not reply to this email.</p>
                        <p>© 2024 Your App Name. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Create plain text version
            text_content = f"""
            Email Verification - OTP Code
            
            Hello {username}!
            
            Thank you for signing up! To complete your registration, please verify your email address using the OTP code below:
            
            Your OTP Code: {otp_code}
            
            Important:
            - This code will expire in 10 minutes
            - Never share this code with anyone
            - If you didn't request this, please ignore this email
            
            Enter this code on the verification page to activate your account.
            
            Best regards,
            The Team
            """

            # Attach parts
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            message.attach(part1)
            message.attach(part2)

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_username, self.email_password)
                server.send_message(message)

            logger.info(f"Verification email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send verification email to {to_email}: {str(e)}")
            return False

    def send_password_reset_email(self, to_email: str, username: str, reset_token: str) -> bool:
        """Send password reset email with secure link"""
        try:
            # Create reset URL (adjust the domain as needed)
            reset_url = f"http://localhost:8000/reset-password?token={reset_token}"
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Reset Your Password - Secure Link"
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email

            # Create HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                    .reset-button {{ display: inline-block; background: #667eea; color: white !important; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }}
                    .reset-button:hover {{ background: #5a67d8; }}
                    .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 30px; }}
                    .token-box {{ background: #f8f9fa; border: 1px solid #e9ecef; padding: 15px; border-radius: 5px; margin: 15px 0; word-break: break-all; font-family: monospace; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Password Reset Request</h1>
                        <p>Secure password reset for your account</p>
                    </div>
                    <div class="content">
                        <h2>Hello {username}!</h2>
                        <p>We received a request to reset your password. If you didn't make this request, you can safely ignore this email.</p>
                        
                        <p>To reset your password, click the button below:</p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_url}" class="reset-button">Reset My Password</a>
                        </div>
                        
                        <p>Or copy and paste this link in your browser:</p>
                        <div class="token-box">{reset_url}</div>
                        
                        <div class="warning">
                            <strong>⚠️ Important Security Information:</strong>
                            <ul>
                                <li>This link will expire in <strong>1 hour</strong></li>
                                <li>This link can only be used <strong>once</strong></li>
                                <li>Never share this link with anyone</li>
                                <li>If you didn't request this reset, please secure your account</li>
                            </ul>
                        </div>
                        
                        <p>If you have any concerns about your account security, please contact our support team immediately.</p>
                        
                        <p>Best regards,<br>The Security Team</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated security message. Please do not reply to this email.</p>
                        <p>If you didn't request a password reset, please ignore this email.</p>
                        <p>© 2024 Your App Name. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Create plain text version
            text_content = f"""
            Password Reset Request
            
            Hello {username}!
            
            We received a request to reset your password. If you didn't make this request, you can safely ignore this email.
            
            To reset your password, visit this link:
            {reset_url}
            
            Important Security Information:
            - This link will expire in 1 hour
            - This link can only be used once
            - Never share this link with anyone
            - If you didn't request this reset, please secure your account
            
            If you have any concerns about your account security, please contact our support team immediately.
            
            Best regards,
            The Security Team
            
            This is an automated security message. Please do not reply to this email.
            """

            # Attach parts
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            message.attach(part1)
            message.attach(part2)

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_username, self.email_password)
                server.send_message(message)

            logger.info(f"Password reset email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send password reset email to {to_email}: {str(e)}")
            return False

# Create global instance
email_service = EmailService() 