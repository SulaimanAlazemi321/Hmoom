"""
Email service for handling verification and password reset emails.

This module provides functionality for sending OTP verification emails
and password reset emails using SMTP.
"""
import smtplib
import secrets
import string
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailService:
    """
    Service class for handling email operations.
    
    Provides methods for sending verification emails, password reset emails,
    and generating secure tokens.
    """
    
    def __init__(self):
        """Initialize email service with configuration from settings."""
        self.smtp_server = settings.EMAIL_HOST
        self.smtp_port = settings.EMAIL_PORT
        self.email_username = settings.EMAIL_USERNAME
        self.email_password = settings.EMAIL_APP_PASSWORD
        self.from_email = settings.EMAIL_FROM
        self.from_name = settings.EMAIL_FROM_NAME

    def generate_otp(self, length: int = 6) -> str:
        """
        Generate a random OTP code.
        
        Args:
            length: Length of the OTP code (default: 6).
            
        Returns:
            String containing random digits.
        """
        return ''.join(secrets.choice(string.digits) for _ in range(length))

    def generate_reset_token(self, length: int = 32) -> str:
        """
        Generate a secure password reset token.
        
        Args:
            length: Length of the token (default: 32).
            
        Returns:
            URL-safe token string.
        """
        return secrets.token_urlsafe(length)

    def test_email_connection(self) -> bool:
        """
        Test email server connection and authentication.
        
        Returns:
            True if connection successful, False otherwise.
        """
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_username, self.email_password)
            logger.info("Email connection test successful")
            return True
        except Exception as e:
            logger.error(f"Email connection test failed: {str(e)}")
            return False

    def send_verification_email(
        self, 
        to_email: str, 
        username: str, 
        otp_code: str
    ) -> bool:
        """
        Send OTP verification email for account activation.
        
        Args:
            to_email: Recipient email address.
            username: Username of the new user.
            otp_code: One-time password code.
            
        Returns:
            True if email sent successfully, False otherwise.
        """
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Verify Your Email Address - OTP Code"
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email

            # Create HTML content
            html_content = self._get_verification_email_html(username, otp_code)
            
            # Create plain text version
            text_content = self._get_verification_email_text(username, otp_code)

            # Attach parts
            message.attach(MIMEText(text_content, "plain"))
            message.attach(MIMEText(html_content, "html"))

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

    def send_password_reset_email(
        self, 
        to_email: str, 
        username: str, 
        reset_token: str
    ) -> bool:
        """
        Send password reset email with secure link.
        
        Args:
            to_email: Recipient email address.
            username: Username of the user.
            reset_token: Secure reset token.
            
        Returns:
            True if email sent successfully, False otherwise.
        """
        try:
            # Create reset URL
            reset_url = f"http://localhost:8000/reset-password?token={reset_token}"
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Reset Your Password - Secure Link"
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email

            # Create HTML content
            html_content = self._get_password_reset_email_html(
                username, reset_url
            )
            
            # Create plain text version
            text_content = self._get_password_reset_email_text(
                username, reset_url
            )

            # Attach parts
            message.attach(MIMEText(text_content, "plain"))
            message.attach(MIMEText(html_content, "html"))

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

    def _get_verification_email_html(self, username: str, otp_code: str) -> str:
        """Generate HTML content for verification email."""
        return f"""
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
                    <p>Welcome to Hmoom!</p>
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
                    
                    <p>Best regards,<br>The Hmoom Team</p>
                </div>
                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>© 2024 Hmoom. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

    def _get_verification_email_text(self, username: str, otp_code: str) -> str:
        """Generate plain text content for verification email."""
        return f"""
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
        The Hmoom Team
        """

    def _get_password_reset_email_html(
        self, 
        username: str, 
        reset_url: str
    ) -> str:
        """Generate HTML content for password reset email."""
        return f"""
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
                    
                    <p>Best regards,<br>The Hmoom Security Team</p>
                </div>
                <div class="footer">
                    <p>This is an automated security message. Please do not reply to this email.</p>
                    <p>If you didn't request a password reset, please ignore this email.</p>
                    <p>© 2024 Hmoom. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

    def _get_password_reset_email_text(
        self, 
        username: str, 
        reset_url: str
    ) -> str:
        """Generate plain text content for password reset email."""
        return f"""
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
        The Hmoom Security Team
        
        This is an automated security message. Please do not reply to this email.
        """


# Create global instance
email_service = EmailService() 