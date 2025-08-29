from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, case, or_, func
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship, joinedload
from flask_caching import Cache
from flask_mail import Mail, Message
from flask_login import LoginManager,UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
import string
from scrapy.selector import Selector
from crawler import crawl, save_to_json
from bs4 import BeautifulSoup
from utils.link_analyzer import analyze_robots_txt
import csv
import json
import re
import logging
import os
import asyncio
import traceback
import random
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import glob
from concurrent.futures import ThreadPoolExecutor
import uuid
from markupsafe import Markup
from sqlalchemy.exc import SQLAlchemyError
from io import BytesIO, StringIO, StringIO as io
from collections import Counter
from datetime import datetime, timedelta, timezone, date
UTC = timezone.utc
import time
from pytz import UTC
import pytz

import decimal 
from urllib.error import URLError
from urllib.parse import quote, urljoin, urlparse

from utils.link_analyzer import analyze_links, analyze_links_with_debug

# Make sure you also have these imports (should already exist):
from utils.text_extractor import extract_text, correct_text, process_keywords
from utils.image_extractor import extract_images
from utils.seo_analyzer import extract_seo_data
from utils.heading_extractor import extract_headings_in_order
from robots_parser import analyze_robots_txt

# Also add this import if you don't have it:
import traceback

import razorpay


from decimal import Decimal, ROUND_HALF_UP
from dateutil.relativedelta import relativedelta
# Import CSRFProtect for CSRF protection
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf


# Import configuration classes
from config import Config, DevelopmentConfig, ProductionConfig

# Initialize app
app = Flask(__name__)

# Configure based on environment
if os.environ.get('FLASK_ENV') == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

# ----------------------
# Initialize other components
# ----------------------
executor = ThreadPoolExecutor(max_workers=5)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'You need to log in to access this page.'
login_manager.login_message_category = 'info'

# Track crawling progress
crawl_status = {}





# For WSGI deployment, expose the Flask app as 'application'
application = app
# Initialize CSRF protection
# Replace your existing CSRF protection code with this:

# You can run this function in a Flask shell or at startup
# To run it when the app starts, add this after your database initialization:
# with app.app_context():
#     cleanup_duplicate_subscriptions()
# Add this to the bottom of your app.py file, before app.run():
# Update your create_app function to initialize website settings
def create_app():
    """Application factory pattern for better deployment"""
    
    with app.app_context():
        try:
            # Create tables
            db.create_all()
            
            # Create super admin if it doesn't exist
            create_super_admin()
            
            # Normalize existing admin emails
            normalize_existing_admin_emails()
            
            # Fix user timestamps
            fix_user_timestamps()
            
            # Initialize website settings
            initialize_website_settings()
            
            # Clean up any duplicate subscriptions
            try:
                deactivated_count = cleanup_duplicate_subscriptions()
                if deactivated_count > 0:
                    app.logger.info(f"Cleaned up {deactivated_count} duplicate subscriptions")
            except Exception as e:
                app.logger.error(f"Error cleaning up subscriptions: {str(e)}")

            # Setup daily cleanup scheduler
            try:
                setup_daily_cleanup_scheduler()
                # Run initial cleanup on startup
                cleanup_crawl_status_memory()
                app.logger.info("Initial cleanup completed on startup")
            except Exception as e:
                app.logger.error(f"Error setting up cleanup scheduler: {str(e)}")
                
        except Exception as e:
            app.logger.error(f"Error during app initialization: {str(e)}")
            
    return app



from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Routes exempt from CSRF (API endpoints, webhooks, etc.)
CSRF_EXEMPT_ROUTES = [
    'api_endpoint',  # Example API route
    'webhook_handler',  # Example webhook
    'url_search_ajax',  # Your AJAX endpoint
    'record_search',   # Your AJAX endpoint
    'get_usage_history',  # Your AJAX endpoint
    'progress',        # Your progress endpoint
    'get_data',        # ADD THIS - Your data endpoint
    'time_and_date_today',  # For /time_and_date_today
    # ADD THESE SUBSCRIPTION ROUTES:
    'user_subscriptions',  # For /subscriptions
    'subscribe',          # For /subscribe/<int:plan_id>
    'checkout',           # For /checkout/<order_id>
    'verify_payment',     # For /payment/verify/<order_id>
    'cancel_subscription', # For /subscription/cancel/<int:subscription_id>
    'change_subscription', # For /subscription/change/<int:new_plan_id>
    'subscription_details', # For /subscription_details/<int:subscription_id>
    'toggle_auto_renew',   # For /subscription/auto-renew/<int:subscription_id>/<int:status>
    'download_invoice',    # For /download_invoice/<int:payment_id>
]
@app.before_request
def csrf_protect():
    """
    Apply CSRF protection with exemptions for specific routes
    """
    # Skip CSRF for exempt routes
    if request.endpoint in CSRF_EXEMPT_ROUTES:
        return
    
    # Skip CSRF for GET requests to public pages
    if request.method == 'GET' and request.endpoint in ['landing', 'about', 'privacy', 'terms']:
        return
    
    # Skip CSRF for AJAX requests that include the X-Requested-With header
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # For AJAX requests, check for CSRF token in headers
        token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')
        if token:
            try:
                csrf.protect()
            except CSRFError:
                return jsonify({'error': 'CSRF token missing or invalid'}), 400
        return
    
    # For all other requests, CSRF is automatically handled by Flask-WTF

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """
    Handle CSRF token validation failures
    """
    # Log the security event for monitoring
    app.logger.warning(
        f"CSRF Token Validation Failed: "
        f"Route: {request.endpoint}, "
        f"Method: {request.method}, "
        f"IP: {request.remote_addr}, "
        f"User-Agent: {request.headers.get('User-Agent', 'Unknown')}"
    )
    
    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'error': 'CSRF token missing or invalid',
            'message': 'Please refresh the page and try again'
        }), 400
    
    # User-friendly error message for regular requests
    flash(
        'Your session has expired or the form submission was invalid. '
        'Please refresh the page and try again.', 
        'danger'
    )
    
    # Context-aware redirection
    if request.endpoint in ['login', 'signup']:
        return redirect(url_for(request.endpoint))
    
    return redirect(url_for('landing'))

# Context processor to make CSRF token available in all templates
@app.context_processor
def inject_csrf_token():
    """Make both csrf_token value and generate_csrf function available in templates"""
    return dict(
        csrf_token=generate_csrf(),  # The actual token as a string
        generate_csrf=generate_csrf  # The function itself
    )

# Add a route to get CSRF token for AJAX requests
@app.route('/get-csrf-token')
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf()})

# Add this decorator for routes that should be exempt from CSRF
from functools import wraps

def csrf_exempt(f):
    """Decorator to exempt a route from CSRF protection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    decorated_function._csrf_exempt = True
    return decorated_function

# Update your before_request function to check for exempt decorator
@app.before_request
def csrf_protect():
    """
    Apply CSRF protection with exemptions for specific routes
    """
    # Skip CSRF for exempt routes
    if request.endpoint in CSRF_EXEMPT_ROUTES:
        return
    
    # Check if the view function has the _csrf_exempt attribute
    view_function = app.view_functions.get(request.endpoint)
    if view_function and getattr(view_function, '_csrf_exempt', False):
        return
    
    # Skip CSRF for GET requests to public pages
    if request.method == 'GET' and request.endpoint in ['landing', 'about', 'privacy', 'terms']:
        return
    
    # Handle AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # For AJAX requests, check for CSRF token in headers or form data
        token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')
        if not token:
            return jsonify({'error': 'CSRF token missing'}), 400

@app.template_filter('to_ist_time')
def to_ist_time(dt):
    """Convert UTC datetime to Indian Standard Time (IST)."""
    if dt is None:
        return "N/A"
    
    # If datetime has no timezone info, assume it's UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    
    # Convert to IST (Asia/Calcutta)
    ist_timezone = pytz.timezone('Asia/Calcutta')
    ist_time = dt.astimezone(ist_timezone)
    
    # Format nicely for display
    return ist_time.strftime('%d %b %Y, %H:%M %p IST')
#----------------------
# Logging configuration
#----------------------
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_app.log')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Flask app started successfully")

# Ensure download directory exists
download_dir = "download_files"
os.makedirs(download_dir, exist_ok=True)

# Configure Flask-Caching (simple in-memory)
app.config['CACHE_TYPE'] = 'simple'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
cache = Cache(app)

# Razorpay configuration - now handled by config classes
razorpay_client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))

# Flask-Mail configuration - now handled by config classes
mail = Mail(app)

# Database configuration - now handled by config classes  
app.config['SQLALCHEMY_DATABASE_URI'] = app.config.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Add connection pool settings for production
if app.config.get('SQLALCHEMY_ENGINE_OPTIONS'):
    for key, value in app.config.get('SQLALCHEMY_ENGINE_OPTIONS').items():
        app.config[f'SQLALCHEMY_{key.upper()}'] = value

# Initialize SQLAlchemy FIRST
db = SQLAlchemy(app)

# NOW call create_app() after db is initialized
application = create_app()


# ----------------------
# Database Model
# ----------------------
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    company_email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirm_token = db.Column(db.String(100), nullable=True)
    email_token_created_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))  
    # Activity tracking fields
    last_login_at = db.Column(db.DateTime, nullable=True)
    profile_updated_at = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    
    def _init_(self, **kwargs):
        # Always normalize email to lowercase when creating a user
        if 'company_email' in kwargs:
            kwargs['company_email'] = kwargs['company_email'].lower().strip()
        super(User, self)._init_(**kwargs)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        # Use timezone-naive datetime to match your database setup
        self.password_changed_at = datetime.now()
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def update_last_login(self):
        """Update the last login timestamp"""
        self.last_login_at = datetime.now(UTC)
        db.session.commit()
    
    def update_profile_timestamp(self):
        """Update the profile updated timestamp"""
        # Use timezone-naive datetime to match your database setup
        self.profile_updated_at = datetime.now()
        # Note: Don't commit here, let the calling function handle the commit
    # Activity display methods
    def get_last_login_display(self):
        """Get formatted last login time"""
        if not self.last_login_at:
            return "Never"
        return self._format_relative_time(self.last_login_at)
    
    def get_profile_updated_display(self):
        """Get formatted profile updated time"""
        if not self.profile_updated_at:
            return "Never"
        return self._format_relative_time(self.profile_updated_at)
    
    def get_password_changed_display(self):
        """Get formatted password changed time"""
        if not self.password_changed_at:
            return "Never"
        return self._format_relative_time(self.password_changed_at)
    
    def _format_relative_time(self, timestamp):
        """Format timestamp to relative time (Today, Yesterday, X days ago, etc.)"""
        if not timestamp:
            return "Never"
        
        # Get current time in the same timezone as the timestamp
        # If timestamp is naive, treat both as naive for comparison
        if timestamp.tzinfo is None:
            # Both naive - use local timezone
            now = datetime.now()
            timestamp = timestamp
        else:
            # Both timezone-aware
            now = datetime.now(UTC)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
        
        # Calculate the difference
        diff = now - timestamp
        
        # Handle negative differences (future timestamps)
        if diff.total_seconds() < 0:
            return "Just now"
        
        total_seconds = int(diff.total_seconds())
        days = diff.days
        
        if days == 0:
            # Same day
            hours = total_seconds // 3600
            if hours == 0:
                minutes = total_seconds // 60
                if minutes == 0:
                    return "Just now"
                elif minutes == 1:
                    return "1 minute ago"
                else:
                    return f"{minutes} minutes ago"
            elif hours == 1:
                return "1 hour ago"
            else:
                return f"{hours} hours ago"
        elif days == 1:
            return "Yesterday"
        elif days < 7:
            return f"{days} days ago"
        elif days < 30:
            weeks = days // 7
            if weeks == 1:
                return "1 week ago"
            else:
                return f"{weeks} weeks ago"
        elif days < 365:
            months = days // 30
            if months == 1:
                return "1 month ago"
            else:
                return f"{months} months ago"
        else:
            years = days // 365
            if years == 1:
                return "1 year ago"
            else:
                return f"{years} years ago"

    # Token Generation
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.secret_key)
        return s.dumps({'user_id': self.id})
    
    # Generate email confirmation token
    def get_email_confirm_token(self):
        s = Serializer(app.secret_key)
        token = s.dumps({'user_id': self.id})
        self.email_confirm_token = token
        self.email_token_created_at = datetime.now(UTC)
        return token

    # Verify email confirmation token
    @staticmethod
    def verify_email_token(token):
        s = Serializer(app.secret_key)
        try:
            user_id = s.loads(token, max_age=86400)['user_id']  # 24 hours expiry
        except:
            return None
        return User.query.get(user_id)

    # Token Verification
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.secret_key)
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            return None
        return User.query.get(user_id)
# Enhanced Subscription Model

class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    
    S_ID = db.Column(db.Integer, primary_key=True)
    plan = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    days = db.Column(db.Integer, nullable=False)
    usage_per_day = db.Column(db.Integer, nullable=False)
    tier = db.Column(db.Integer, nullable=False)  # Added tier for upgrade/downgrade logic
    features = db.Column(db.Text, nullable=True)  # JSON string of features
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    archived_at = db.Column(db.DateTime, nullable=True)
    # Relationship with SubscribedUser
    subscribed_users = relationship("SubscribedUser", back_populates="subscription", overlaps="subscribers")
    
    def __repr__(self):
        return f"<Subscription {self.plan}>"
        
    @property
    def daily_price(self):
        """Calculate price per day"""
        return self.price / self.days if self.days > 0 else 0


class SubscribedUser(db.Model):
    __tablename__ = 'subscribed_users'
    
    id = db.Column(db.Integer, primary_key=True)
    U_ID = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    S_ID = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.now(UTC))
    end_date = db.Column(db.DateTime, nullable=False)
    current_usage = db.Column(db.Integer, default=0)
    last_usage_reset = db.Column(db.DateTime, default=datetime.now(UTC))
    is_auto_renew = db.Column(db.Boolean, default=True)
    _is_active = db.Column('is_active', db.Boolean, default=True, nullable=False)

    # Relationships
    user = db.relationship('User', backref=db.backref('subscriptions', lazy=True))
    subscription = db.relationship('Subscription', backref=db.backref('subscribers', lazy=True))

    
    
    def remaining_value(self):
        now = datetime.now(UTC)
        
        # Ensure both start_date and end_date are timezone-aware
        start_date = self.start_date.replace(tzinfo=UTC) if self.start_date.tzinfo is None else self.start_date
        end_date = self.end_date.replace(tzinfo=UTC) if self.end_date.tzinfo is None else self.end_date
        
        if end_date <= now:
            return 0
        
        # Calculate total days in subscription period
        total_days = (end_date - start_date).total_seconds() / (24 * 3600)
        
        # Calculate remaining days
        remaining_days = (end_date - now).total_seconds() / (24 * 3600)
        
        # Calculate the daily rate and remaining value
        subscription = Subscription.query.get(self.S_ID)
        daily_rate = subscription.price / total_days if total_days > 0 else 0
        
        return daily_rate * remaining_days
    
    @property
    def daily_usage_percent(self):
        """
        Calculate the percentage of daily usage
        """
        if not hasattr(self.subscription, 'usage_per_day') or not self.subscription.usage_per_day:
            return 0
            
        return min(100, (self.current_usage / self.subscription.usage_per_day) * 100)
    
    @property
    def is_active(self):
        now = datetime.now(timezone.utc)
        end_date = self.end_date

        if end_date and end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=timezone.utc)

        return self._is_active and end_date > now
    @is_active.setter
    def is_active(self, value):
        """
        Setter for is_active that only updates the underlying _is_active column
        """
        self._is_active = value

    @property
    def days_remaining(self):
        """
        Calculate the number of days remaining in the subscription
        """
        now = datetime.now(UTC)
        
        # Ensure end_date is timezone-aware
        if self.end_date.tzinfo is None:
            # If end_date is naive, make it timezone-aware using UTC
            end_date = self.end_date.replace(tzinfo=UTC)
        else:
            end_date = self.end_date
        
        if end_date <= now:
            return 0
        
        # Use total_seconds() to handle timezone-aware dates
        remaining_seconds = (end_date - now).total_seconds()
        return max(0, int(remaining_seconds / (24 * 3600)))

class InvoiceAddress(db.Model):
    __tablename__ = 'invoice_addresses'
    
    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.iid'), nullable=False)  # Updated to 'payments.iid'
    
    # Billing Address Details
    company_name = db.Column(db.String(255), nullable=True)
    full_name = db.Column(db.String(255), nullable=False)
    street_address = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), default='India')
    
    # Additional Contact Information
    email = db.Column(db.String(255), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    
    # Tax Identification Numbers
    gst_number = db.Column(db.String(20), nullable=True)
    pan_number = db.Column(db.String(20), nullable=True)
    
    # Relationship
    payment = relationship("Payment", back_populates="invoice_address")

    
class Payment(db.Model):
    __tablename__ = 'payments'
    
    iid = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID', ondelete='SET NULL'), nullable=False)
    razorpay_order_id = db.Column(db.String(100), nullable=False)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    
    # Invoice-specific Details
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    invoice_date = db.Column(db.DateTime, default=datetime.now(UTC))
    
    # Extended Payment Information
    order_number = db.Column(db.String(50), nullable=True)
    customer_number = db.Column(db.String(50), nullable=True)
    purchase_order = db.Column(db.String(50), nullable=True)
    payment_terms = db.Column(db.String(100), default='Credit Card')
    
    # Base amount and tax calculations
    base_amount = db.Column(db.Float, nullable=False)
    gst_rate = db.Column(db.Float, default=0.18)  # Default 18% GST
    gst_amount = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    
    # Additional tax-related information
    hsn_code = db.Column(db.String(20), nullable=True)
    cin_number = db.Column(db.String(50), nullable=True)
    
    currency = db.Column(db.String(10), default='INR')
    status = db.Column(db.String(20), default='created')
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    payment_type = db.Column(db.String(20), default='new')
    previous_subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=True)
    credit_applied = db.Column(db.Float, default=0.0)
    
    # Additional notes or special instructions
    notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    user = relationship("User", backref="payments")
    subscription = relationship("Subscription", foreign_keys=[subscription_id], backref="payments")
    previous_subscription = relationship("Subscription", foreign_keys=[previous_subscription_id])
    invoice_address = relationship("InvoiceAddress", back_populates="payment", uselist=False)
    
    def __init__(self, *args, **kwargs):
        # Get the base_amount from kwargs with a default value of 0
        base_amount = kwargs.pop('base_amount', 0)
        gst_rate = kwargs.pop('gst_rate', 0.18)
        
        # Validate inputs more robustly
        try:
            base_amount = float(base_amount)
            if base_amount < 0:
                raise ValueError("Base amount must be a non-negative number")
        except (TypeError, ValueError):
            raise ValueError("Invalid base amount provided")
        
        super().__init__(*args, **kwargs)
        
        self.base_amount = base_amount
        self.gst_rate = gst_rate
        
        self._generate_invoice_details()
        self._calculate_total_amount()
    
    def _generate_invoice_details(self):
        """
        Generate unique invoice details with more robust generation
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d")
        unique_id = str(uuid.uuid4().hex)[:6].upper()
        self.invoice_number = f"INV-{timestamp}-{unique_id}"
        self.invoice_date = datetime.now(UTC)
    
    def _calculate_total_amount(self):
        """
        Enhanced total amount calculation with comprehensive error handling
        """
        try:
            base = Decimal(str(self.base_amount)).quantize(Decimal('0.01'))
            gst_rate = Decimal(str(self.gst_rate)).quantize(Decimal('0.01'))
            
            gst_amount = base * gst_rate
            gst_amount = gst_amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            
            total_amount = base + gst_amount
            total_amount = total_amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            
            self.gst_amount = float(gst_amount)
            self.total_amount = float(total_amount)
        except (TypeError, ValueError, decimal.InvalidOperation) as e:
            # Log the error and set default values
            print(f"Error in amount calculation: {e}")
            self.gst_amount = 0
            self.total_amount = self.base_amount
    
    def generate_invoice_pdf(self):
        """
        Placeholder method for generating invoice PDF
        Can be implemented with a library like ReportLab
        """
        # Future implementation for PDF generation
        pass
    
    def get_invoice_summary(self):
        """
        Return a comprehensive invoice summary
        
        :return: Dictionary with invoice details
        """
        return {
            'invoice_number': self.invoice_number,
            'invoice_date': self.invoice_date,
            'order_number': self.order_number,
            'customer_number': self.customer_number,
            'base_amount': self.base_amount,
            'gst_rate': self.gst_rate * 100,
            'gst_amount': self.gst_amount,
            'total_amount': self.total_amount,
            'currency': self.currency,
            'status': self.status
        }
    
    def __repr__(self):
        return f"<Payment {self.invoice_number} - {self.total_amount}>"

# Subscription History to track changes
class SubscriptionHistory(db.Model):
    __tablename__ = 'subscription_history'
    
    id = db.Column(db.Integer, primary_key=True)
    U_ID = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    S_ID = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # new, upgrade, downgrade, cancel, expire
    previous_S_ID = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    
    # Relationships
    user = relationship("User", backref="subscription_history")
    subscription = relationship("Subscription", foreign_keys=[S_ID])
    previous_subscription = relationship("Subscription", foreign_keys=[previous_S_ID])
    
    def __repr__(self):
        return f"<SubscriptionHistory {self.action} for {self.user.name}>"



# Update the SearchHistory model
class SearchHistory(db.Model):
    __tablename__ = 'search_history'  # Add this line to explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    u_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_name = db.Column(db.String(100), nullable=False)
    usage_tool = db.Column(db.String(100), nullable=False)
    search_history = db.Column(db.String(255), nullable=False)
    search_count = db.Column(db.Integer, default=1)
    # Store UTC time
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
   
    # Relationship to User for easy access to user details
    user = db.relationship('User', backref='search_histories')
   
    # Property to get IST time
    @property
    def ist_time(self):
        # Add 5 hours and 30 minutes to UTC time to get IST
        if self.created_at:
            if self.created_at.tzinfo is None:  # If naive datetime
                return pytz.timezone('UTC').localize(self.created_at).astimezone(pytz.timezone('Asia/Kolkata'))
            return self.created_at.astimezone(pytz.timezone('Asia/Kolkata'))
        return None
    
    def __repr__(self):
        return f"<SearchHistory id={self.id}, u_id={self.u_id}, usage_tool='{self.usage_tool}', search_count={self.search_count}>"

# 1. First, update the TokenPurchase model to include invoice functionality
class TokenPurchase(db.Model):
    __tablename__ = 'token_purchases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscribed_users.id'), nullable=False)
    token_count = db.Column(db.Integer, nullable=False)
    base_amount = db.Column(db.Float, nullable=False)
    gst_amount = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    razorpay_order_id = db.Column(db.String(100), nullable=False)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='created')  # created, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    
    # Add invoice fields
    invoice_number = db.Column(db.String(50), unique=True, nullable=True)
    invoice_date = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='token_purchases')
    subscription = db.relationship('SubscribedUser', backref='token_purchases')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.status == 'completed' and not self.invoice_number:
            self._generate_invoice_details()
    
    def _generate_invoice_details(self):
        """Generate invoice details for token purchase"""
        timestamp = datetime.now(UTC).strftime("%Y%m%d")
        unique_id = str(uuid.uuid4().hex)[:6].upper()
        self.invoice_number = f"TKN-{timestamp}-{unique_id}"
        self.invoice_date = datetime.now(UTC)
    
    def __repr__(self):
        return f"<TokenPurchase {self.id}: {self.token_count} tokens for user {self.user_id}>"


# Add this to your UserToken model in app.py (around line 700)

class UserToken(db.Model):
    __tablename__ = 'user_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscribed_users.id'), nullable=False)
    purchase_id = db.Column(db.Integer, db.ForeignKey('token_purchases.id'), nullable=False)
    tokens_purchased = db.Column(db.Integer, nullable=False)
    tokens_used = db.Column(db.Integer, default=0)
    tokens_remaining = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    expires_at = db.Column(db.DateTime, nullable=False)  # Keep this for reference
    
    # ADD THESE NEW FIELDS
    is_paused = db.Column(db.Boolean, default=False)  # Whether tokens are paused
    paused_at = db.Column(db.DateTime, nullable=True)  # When tokens were paused
    original_subscription_id = db.Column(db.Integer, nullable=True)  # Original subscription that purchased these tokens
    
    # Relationships
    user = db.relationship('User', backref='user_tokens')
    subscription = db.relationship('SubscribedUser', backref='user_tokens')
    purchase = db.relationship('TokenPurchase', backref='user_tokens')
    
    def pause_tokens(self):
        """Pause unused tokens when subscription expires"""
        if self.tokens_remaining > 0 and not self.is_paused:
            self.is_paused = True
            self.paused_at = datetime.now(UTC)
            if not self.original_subscription_id:
                self.original_subscription_id = self.subscription_id
    
    def reactivate_tokens(self, new_subscription_id):
        """Reactivate paused tokens for new subscription"""
        if self.is_paused and self.tokens_remaining > 0:
            self.is_paused = False
            self.subscription_id = new_subscription_id
            # Extend expiry to new subscription's end date
            new_subscription = SubscribedUser.query.get(new_subscription_id)
            if new_subscription:
                self.expires_at = new_subscription.end_date
    
    def __repr__(self):
        status = "PAUSED" if self.is_paused else "ACTIVE"
        return f"<UserToken {self.id}: {self.tokens_remaining}/{self.tokens_purchased} remaining - {status}>"
# ----------------------
# Search history
# ----------------------

def add_search_history(user_id, usage_tool, search_query):
    """Logs every search performed by a user with full timestamp."""
    if not user_id:
        return False

    try:
        # Fetch user or fallback to "Guest"
        user = db.session.get(User, user_id)
        user_name = user.name if user else "Guest"

        # Create a new SearchHistory entry (always)
        entry = SearchHistory(
            u_id=user_id,
            user_name=user_name,
            usage_tool=usage_tool,
            search_history=search_query,
            search_count=1,
            created_at=datetime.now(timezone.utc)  # Use current UTC time
        )

        db.session.add(entry)
        db.session.commit()
        return True

    except SQLAlchemyError as e:
        print(f"Error logging search history: {e}")
        db.session.rollback()
        return False

#-----------------------
# Admin calss DB schema
#-----------------------
class UsageLog(db.Model):
    __tablename__ = 'usage_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscribed_users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(UTC))
    operation_type = db.Column(db.String(100), nullable=False)  # e.g., 'url_analysis', 'keyword_search', etc.
    details = db.Column(db.Text, nullable=True)  # Additional details in JSON format
    
    # Relationships
    user = db.relationship('User', backref=db.backref('usage_logs', lazy=True))
    subscription = db.relationship('SubscribedUser', backref=db.backref('usage_logs', lazy=True))
    
    def __repr__(self):
        return f"<UsageLog id={self.id}, user_id={self.user_id}, operation={self.operation_type}>"
# ----------------------
# Define the Admin model
# Admin class DB schema
# ----------------------
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy import JSON

class Admin(db.Model):
    __tablename__ = 'admin'

    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.String(120), nullable=False, unique=True)
    NAME = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    assigned_by = db.Column(db.String(50), nullable=False)
    permission = db.Column(db.ARRAY(db.String(50))) 
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    updated_at = db.Column(db.DateTime, onupdate=datetime.now(UTC))
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        """Set the password hash."""
        if password and password.strip():
            try:
                self.password_hash = generate_password_hash(password)
                return True
            except Exception as e:
                app.logger.error(f"Password hashing error: {str(e)}")
                return False
        return False
    def check_password(self, password):
        """Check the password against the stored hash."""
        if not self.password_hash or not password:
            return False
        try:
            return check_password_hash(self.password_hash, password)
        except Exception as e:
            app.logger.error(f"Password check error: {str(e)}")
            return False
    def admin_permissions(self, required_permission):
        """
        Check if the admin has the specified permission based on their email and stored permissions
        """
        if request.method == 'POST':
            email_id = request.form.get('email_id')
            permissions = request.form.getlist('permissions[]')
            
            # Check if this instance's email matches the form email
            if self.email_id == email_id:
                return required_permission in permissions
            
        # For non-POST requests or if emails don't match, check stored permissions
        return required_permission in self.permission if self.permission else False

    @staticmethod
    def check_permission(email_id, required_permission):
        """Static method to check permissions by email"""
        admin = Admin.query.filter_by(email_id=email_id).first()
        if not admin:
            return False
            
        # For POST requests, check against form data
        if request.method == 'POST':
            form_email = request.form.get('email_id')
            if form_email == email_id:
                permissions = request.form.getlist('permissions[]')
                return required_permission in permissions
                
        # Otherwise check stored permissions
        return admin.admin_permissions(required_permission)

    def __repr__(self):
        return f"<Admin {self.NAME} - {self.role}>"


class ContactSubmission(db.Model):
    __tablename__ = 'contact_submissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(20), default='new')
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    responded_at = db.Column(db.DateTime, nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f"<ContactSubmission {self.name} - {self.email}>"
    
# Update your create_super_admin function in app.py to include the new permission

def create_super_admin():
    """
    Create a super admin user if it doesn't already exist
    """
    # Check if super admin already exists
    super_admin_email = "Nithyalakshmi22sk@gmail.com"  # Change this to your desired email
    existing_admin = Admin.query.filter_by(email_id=super_admin_email).first()
    
    if existing_admin:
        # Update existing super admin with new permission if needed
        current_permissions = existing_admin.permission if existing_admin.permission else []
        if "website_settings" not in current_permissions:
            current_permissions.append("website_settings")
            existing_admin.permission = current_permissions
            db.session.commit()
            logging.info("Updated super admin with website_settings permission")
        logging.info("Super admin already exists")
        return
    
    # Create super admin with all permissions including the new one
    super_admin = Admin(
        email_id=super_admin_email,
        NAME="Super Admin",
        role="Super Admin",
        phone_number="8122156835",  # Change this if needed
        assigned_by="System",
        permission=[
            "dashboard",
            "manage_roles", 
            "subscription_management", 
            "subscribed_users_view", 
            "user_management",
            "payments",
            "contact_submissions",
            "website_settings"  # ADD THIS NEW PERMISSION
        ],  
        is_active=True,
        created_at=datetime.utcnow()
    )
    
    # Set a password - CHANGE THIS TO A STRONG PASSWORD!
    super_admin_password = "Nithya@22092001"  # CHANGE THIS!
    super_admin.set_password(super_admin_password)
    
    # Add and commit
    try:
        db.session.add(super_admin)
        db.session.commit()
        logging.info(f"Super admin created successfully: {super_admin_email}")
        print(f"Super admin created successfully: {super_admin_email}")
        print(f"Password: {super_admin_password}")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating super admin: {str(e)}")
        print(f"Error creating super admin: {str(e)}")


# Add this model to your app.py file (around line 600, after other models)

class WebsiteSettings(db.Model):
    __tablename__ = 'website_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=True)
    setting_type = db.Column(db.String(50), default='text')  # text, file, json, etc.
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    updated_at = db.Column(db.DateTime, default=datetime.now(UTC), onupdate=datetime.now(UTC))
    updated_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    
    # Relationship to admin who made the change
    updated_by_admin = db.relationship('Admin', backref='settings_updates')
    
    def __repr__(self):
        return f"<WebsiteSettings {self.setting_key}={self.setting_value}>"
    
    @staticmethod
    def get_setting(key, default=None):
        """Get a setting value by key"""
        setting = WebsiteSettings.query.filter_by(setting_key=key).first()
        return setting.setting_value if setting else default
    
    @staticmethod
    def set_setting(key, value, admin_id=None, description=None, setting_type='text'):
        """Set or update a setting"""
        setting = WebsiteSettings.query.filter_by(setting_key=key).first()
        
        if setting:
            setting.setting_value = value
            setting.updated_at = datetime.now(UTC)
            setting.updated_by = admin_id
            if description:
                setting.description = description
        else:
            setting = WebsiteSettings(
                setting_key=key,
                setting_value=value,
                setting_type=setting_type,
                description=description,
                updated_by=admin_id
            )
            db.session.add(setting)
        
        db.session.commit()
        return setting

# Add this function to initialize default settings
def initialize_website_settings():
    """Initialize default website settings if they don't exist"""
    default_settings = [
        {
            'key': 'website_name',
            'value': 'Web Analyzer Pro',
            'type': 'text',
            'description': 'The main website name displayed in headers and titles'
        },
        {
            'key': 'website_icon',
            'value': 'fas fa-chart-line',
            'type': 'text',
            'description': 'FontAwesome icon class for the website logo'
        },
        {
            'key': 'website_logo_file',
            'value': None,
            'type': 'file',
            'description': 'Custom logo image file (optional, overrides icon)'
        },
        {
            'key': 'website_tagline',
            'value': 'Professional Web Analysis Tools',
            'type': 'text',
            'description': 'Website tagline or description'
        }
    ]
    
    for setting in default_settings:
        existing = WebsiteSettings.query.filter_by(setting_key=setting['key']).first()
        if not existing:
            WebsiteSettings.set_setting(
                key=setting['key'],
                value=setting['value'],
                setting_type=setting['type'],
                description=setting['description']
            )
    
    app.logger.info("Website settings initialized")

# ----------------------
#custom email validation
# ----------------------

# Replace your existing send_verification_email function in app.py with this enhanced version

def send_verification_email(user):
    """Send email verification with enhanced error handling and HTML template"""
    try:
        token = user.get_email_confirm_token()
        
        msg = Message('Email Verification - Fourth Dimension',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[user.company_email])
        
        # Text version for email clients that don't support HTML
        msg.body = f'''Hello {user.name},

Thank you for signing up with Fourth Dimension!

To verify your email address, please click the following link:

{url_for('verify_email', token=token, _external=True)}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

Thanks,
Fourth Dimension Team
'''
        
        # HTML version for better presentation
        msg.html = f'''
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Email Verification</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9ff;">
                    <div style="background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <h1 style="color: #4f46e5; margin: 0;">Fourth Dimension</h1>
                            <p style="color: #6b7280; margin: 5px 0 0 0;">Web Analysis Platform</p>
                        </div>
                        
                        <h2 style="color: #4f46e5; margin-bottom: 20px;">Welcome to Fourth Dimension!</h2>
                        
                        <p style="margin-bottom: 20px;">Hello <strong>{user.name}</strong>,</p>
                        
                        <p style="margin-bottom: 25px;">Thank you for signing up with Fourth Dimension! To complete your account setup and start analyzing websites, please verify your email address by clicking the button below.</p>
                        
                        <div style="text-align: center; margin: 35px 0;">
                            <a href="{url_for('verify_email', token=token, _external=True)}" 
                               style="background-color: #4f46e5; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600; font-size: 16px;">
                                Verify Email Address
                            </a>
                        </div>
                        
                        <p style="margin-bottom: 20px; font-size: 14px; color: #6b7280;">
                            If the button doesn't work, you can copy and paste this link into your browser:
                        </p>
                        <p style="word-break: break-all; color: #4f46e5; background-color: #f3f4f6; padding: 10px; border-radius: 5px; font-size: 13px;">
                            {url_for('verify_email', token=token, _external=True)}
                        </p>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                            <p style="margin-bottom: 10px; color: #ef4444; font-weight: 600;">⚠️ Important:</p>
                            <ul style="color: #6b7280; font-size: 14px; margin: 0; padding-left: 20px;">
                                <li>This verification link will expire in 24 hours</li>
                                <li>If you did not create an account, please ignore this email</li>
                                <li>For security reasons, do not share this link with anyone</li>
                            </ul>
                        </div>
                        
                        <div style="margin-top: 30px; text-align: center; color: #6b7280; font-size: 12px;">
                            <p style="margin: 0;">Thanks,<br><strong>Fourth Dimension Team</strong></p>
                            <p style="margin: 10px 0 0 0;">Need help? Contact us at support@fourthdimension.com</p>
                        </div>
                    </div>
                </div>
            </body>
        </html>
        '''
        
        # Send the email
        mail.send(msg)
        logging.info(f"Verification email sent successfully to {user.company_email}")
        
    except Exception as e:
        logging.error(f"Failed to send verification email to {user.company_email}: {str(e)}")
        # Log the full traceback for debugging
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        raise  # Re-raise the exception so the calling code can handle it
# Add this function to your app.py file (around line 1000, near your other email functions)

def send_reset_email(user):
    """Send password reset email with enhanced error handling and HTML template"""
    try:
        token = user.get_reset_token()
        
        msg = Message('Password Reset Request - Fourth Dimension',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[user.company_email])
        
        # Text version for email clients that don't support HTML
        msg.body = f'''Hello {user.name},

You have requested a password reset for your Fourth Dimension account.

To reset your password, please click the following link:

{url_for('reset_token', token=token, _external=True)}

This link will expire in 30 minutes.

If you did not request this password reset, please ignore this email and your password will remain unchanged.

Thanks,
Fourth Dimension Team
'''
        
        # HTML version for better presentation
        msg.html = f'''
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset Request</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9ff;">
                    <div style="background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <h1 style="color: #4f46e5; margin: 0;">Fourth Dimension</h1>
                            <p style="color: #6b7280; margin: 5px 0 0 0;">Web Analysis Platform</p>
                        </div>
                        
                        <h2 style="color: #ef4444; margin-bottom: 20px;">Password Reset Request</h2>
                        
                        <p style="margin-bottom: 20px;">Hello <strong>{user.name}</strong>,</p>
                        
                        <p style="margin-bottom: 25px;">You have requested a password reset for your Fourth Dimension account. Click the button below to create a new password.</p>
                        
                        <div style="text-align: center; margin: 35px 0;">
                            <a href="{url_for('reset_token', token=token, _external=True)}" 
                               style="background-color: #ef4444; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600; font-size: 16px;">
                                Reset Password
                            </a>
                        </div>
                        
                        <p style="margin-bottom: 20px; font-size: 14px; color: #6b7280;">
                            If the button doesn't work, you can copy and paste this link into your browser:
                        </p>
                        <p style="word-break: break-all; color: #4f46e5; background-color: #f3f4f6; padding: 10px; border-radius: 5px; font-size: 13px;">
                            {url_for('reset_token', token=token, _external=True)}
                        </p>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                            <p style="margin-bottom: 10px; color: #ef4444; font-weight: 600;">⚠️ Important Security Notice:</p>
                            <ul style="color: #6b7280; font-size: 14px; margin: 0; padding-left: 20px;">
                                <li>This password reset link will expire in 30 minutes</li>
                                <li>If you did not request this password reset, please ignore this email</li>
                                <li>Your password will remain unchanged unless you click the link above</li>
                                <li>For security reasons, do not share this link with anyone</li>
                            </ul>
                        </div>
                        
                        <div style="margin-top: 30px; text-align: center; color: #6b7280; font-size: 12px;">
                            <p style="margin: 0;">Thanks,<br><strong>Fourth Dimension Team</strong></p>
                            <p style="margin: 10px 0 0 0;">Need help? Contact us at support@fourthdimension.com</p>
                        </div>
                    </div>
                </div>
            </body>
        </html>
        '''
        
        # Send the email
        mail.send(msg)
        logging.info(f"Password reset email sent successfully to {user.company_email}")
        
    except Exception as e:
        logging.error(f"Failed to send password reset email to {user.company_email}: {str(e)}")
        # Log the full traceback for debugging
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        raise  # Re-raise the exception so the calling code can handle it

# Replace the existing send_token_purchase_confirmation_email function in app.py (around line 1200)

def send_token_purchase_confirmation_email(user, token_purchase):
    """Send token purchase confirmation email using template"""
    try:
        subject = f"Token Purchase Confirmation - {token_purchase.token_count} Additional Tokens"
        
        message = Message(
            subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[user.company_email]
        )
        
        # Text version for email clients that don't support HTML
        message.body = f"""Dear {user.name},

Great news! Your token purchase has been processed successfully. You now have {token_purchase.token_count} additional tokens available in your account.

Purchase Details:
- Tokens Purchased: {token_purchase.token_count} tokens
- Amount Paid: ₹{token_purchase.total_amount}
- Invoice Number: {token_purchase.invoice_number}
- Purchase Date: {token_purchase.created_at.strftime('%d %b %Y, %H:%M UTC')}
- Order ID: {token_purchase.razorpay_order_id}

How Your Tokens Work:
✅ Tokens are immediately available in your account
⏰ Valid for 1 year from purchase date
🔄 Used automatically when daily quota is exhausted
📊 Track usage in your subscription dashboard

You can view your dashboard and download your invoice from your account.

Thanks for choosing Web Analyzer Pro!

The Web Analyzer Pro Team
Need help? Contact us at support@webanalyzerpro.com
"""
        
        # HTML version using the template content directly
        message.html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Token Purchase Confirmation</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9ff;">
        <div style="background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #4f46e5; margin: 0;">Web Analyzer Pro</h1>
                <p style="color: #6b7280; margin: 5px 0 0 0;">Token Purchase Confirmation</p>
            </div>
            
            <h2 style="color: #059669; margin-bottom: 20px;">🎉 Token Purchase Successful!</h2>
            
            <p style="margin-bottom: 20px;">Hello <strong>{user.name}</strong>,</p>
            
            <p style="margin-bottom: 25px;">Great news! Your token purchase has been processed successfully. You now have <strong>{token_purchase.token_count} additional tokens</strong> available in your account.</p>
            
            <div style="background-color: #f0fdf4; padding: 20px; border-radius: 8px; border-left: 4px solid #059669; margin: 25px 0;">
                <h3 style="color: #047857; margin: 0 0 15px 0;">Purchase Details</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px 0; font-weight: 600; color: #374151;">Tokens Purchased:</td>
                        <td style="padding: 8px 0; color: #059669; font-weight: bold;">{token_purchase.token_count} tokens</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: 600; color: #374151;">Amount Paid:</td>
                        <td style="padding: 8px 0;">₹{token_purchase.total_amount}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: 600; color: #374151;">Invoice Number:</td>
                        <td style="padding: 8px 0;">{token_purchase.invoice_number}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: 600; color: #374151;">Purchase Date:</td>
                        <td style="padding: 8px 0;">{token_purchase.created_at.strftime('%d %b %Y, %H:%M UTC')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: 600; color: #374151;">Order ID:</td>
                        <td style="padding: 8px 0; font-size: 12px;">{token_purchase.razorpay_order_id}</td>
                    </tr>
                </table>
            </div>
            
            <div style="background-color: #eff6ff; padding: 20px; border-radius: 8px; border-left: 4px solid #3b82f6; margin: 25px 0;">
                <h3 style="color: #1e40af; margin: 0 0 15px 0;">How Your Tokens Work</h3>
                <ul style="margin: 0; padding-left: 20px; color: #374151;">
                    <li style="margin-bottom: 8px;">✅ Tokens are immediately available in your account</li>
                    <li style="margin-bottom: 8px;">⏰ Valid for 1 year from purchase date</li>
                    <li style="margin-bottom: 8px;">🔄 Used automatically when daily quota is exhausted</li>
                    <li style="margin-bottom: 8px;">📊 Track usage in your subscription dashboard</li>
                </ul>
            </div>
            
            <div style="text-align: center; margin: 35px 0;">
                <a href="{url_for('user_subscriptions', _external=True)}" 
                   style="background-color: #4f46e5; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600; font-size: 16px; margin-right: 10px;">
                    View Dashboard
                </a>
                <a href="{url_for('download_token_invoice', token_purchase_id=token_purchase.id, _external=True)}" 
                   style="background-color: #059669; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600; font-size: 16px;">
                    Download Invoice
                </a>
            </div>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                <p style="margin-bottom: 10px; color: #374151; font-weight: 600;">💡 Pro Tips:</p>
                <ul style="color: #6b7280; font-size: 14px; margin: 0; padding-left: 20px;">
                    <li>Your tokens will be used automatically when daily limits are reached</li>
                    <li>Monitor your token usage in the subscription dashboard</li>
                    <li>Consider purchasing tokens in advance for heavy usage periods</li>
                    <li>Contact support if you have any questions about token usage</li>
                </ul>
            </div>
            
            <div style="margin-top: 30px; text-align: center; color: #6b7280; font-size: 12px;">
                <p style="margin: 0;">Thanks for choosing Web Analyzer Pro!<br><strong>The Web Analyzer Pro Team</strong></p>
                <p style="margin: 10px 0 0 0;">Need help? Contact us at support@webanalyzerpro.com</p>
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        mail.send(message)
        app.logger.info(f"Token purchase confirmation email sent to {user.company_email}")
        
    except Exception as e:
        app.logger.error(f"Failed to send token purchase confirmation email: {str(e)}")
        # Log the full traceback for debugging
        import traceback
        app.logger.error(f"Email sending traceback: {traceback.format_exc()}")
        raise

# Add this route to your app.py for testing email functionality
# Remove this route in production

@app.route('/debug/test_token_email')
@login_required
def test_token_email():
    """Test route to verify token purchase email is working (REMOVE IN PRODUCTION)"""
    if not app.debug:
        return "Debug mode only", 404
    
    try:
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Find a completed token purchase for this user
        token_purchase = TokenPurchase.query.filter_by(
            user_id=user_id,
            status='completed'
        ).first()
        
        if not token_purchase:
            # Create a mock token purchase for testing
            from datetime import datetime, timezone
            token_purchase = type('MockTokenPurchase', (), {
                'id': 999,
                'token_count': 25,
                'total_amount': 50.00,
                'invoice_number': f'TKN-TEST-{int(time.time())}',
                'created_at': datetime.now(timezone.utc),
                'razorpay_order_id': 'order_test_123456789'
            })()
        
        # Test email configuration first
        try:
            # Check if mail configuration is properly set
            mail_config = {
                'MAIL_SERVER': app.config.get('MAIL_SERVER'),
                'MAIL_PORT': app.config.get('MAIL_PORT'),
                'MAIL_USE_TLS': app.config.get('MAIL_USE_TLS'),
                'MAIL_USE_SSL': app.config.get('MAIL_USE_SSL'),
                'MAIL_USERNAME': app.config.get('MAIL_USERNAME'),
                'MAIL_PASSWORD': '***HIDDEN***' if app.config.get('MAIL_PASSWORD') else None,
            }
            
            app.logger.info(f"Mail configuration: {mail_config}")
            
            # Try to send the email
            send_token_purchase_confirmation_email(user, token_purchase)
            
            return jsonify({
                'success': True,
                'message': f'Test email sent successfully to {user.company_email}',
                'mail_config': mail_config,
                'user_email': user.company_email
            })
            
        except Exception as email_error:
            import traceback
            return jsonify({
                'success': False,
                'error': str(email_error),
                'traceback': traceback.format_exc(),
                'mail_config': mail_config,
                'user_email': user.company_email
            }), 500
            
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


# Also add this function to check email configuration
def check_email_configuration():
    """Check if email configuration is properly set up"""
    required_config = [
        'MAIL_SERVER',
        'MAIL_PORT', 
        'MAIL_USERNAME',
        'MAIL_PASSWORD'
    ]
    
    missing_config = []
    for config_key in required_config:
        if not app.config.get(config_key):
            missing_config.append(config_key)
    
    if missing_config:
        app.logger.error(f"Missing email configuration: {missing_config}")
        return False, missing_config
    
    return True, []    
#----------------------
# Custom Filter Registration
# ----------------------
def highlight_keywords(text, keywords_colors):
    """
    Wrap each occurrence of each keyword (case-insensitive) in the text with a <span> tag
    that styles it with the specified color and bold font.
    The matched text preserves its original case.
    """
    highlighted = text
    for keyword, color in keywords_colors.items():
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        highlighted = pattern.sub(
            lambda m: f'<span style="color: {color}; font-weight: bold;">{m.group(0)}</span>',
            highlighted
        )
    return Markup(highlighted)

app.jinja_env.filters['highlight_keywords'] = highlight_keywords

def load_results():
    """Load crawl results with enhanced error handling and debugging."""
    job_id = session.get('job_id')
    app.logger.info(f"Loading results for job_id: {job_id}")
    
    if not job_id:
        app.logger.warning("No job_id found in session")
        return {"status_codes": {}, "home_links": {}, "other_links": {}}
    
    # Ensure crawled_data directory exists
    crawled_data_dir = "crawled_data"
    if not os.path.exists(crawled_data_dir):
        app.logger.error(f"Crawled data directory does not exist: {crawled_data_dir}")
        os.makedirs(crawled_data_dir, exist_ok=True)
        return {"status_codes": {}, "home_links": {}, "other_links": {}}
    
    # Build the JSON file path using the job ID
    crawled_data = f"crawled_data/crawl_{job_id}.json"
    app.logger.info(f"Looking for data file: {crawled_data}")
    
    if os.path.exists(crawled_data):
        try:
            # Check file size
            file_size = os.path.getsize(crawled_data)
            app.logger.info(f"Data file size: {file_size} bytes")
            
            if file_size == 0:
                app.logger.error(f"Data file is empty: {crawled_data}")
                return {"status_codes": {}, "home_links": {}, "other_links": {}}
            
            # **ENHANCED FILE READING WITH RETRY**
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    with open(crawled_data, "r", encoding="utf-8") as file:
                        data = json.load(file)
                        app.logger.info(f"Successfully loaded data from {crawled_data}")
                        
                        # **VALIDATE LOADED DATA**
                        if not isinstance(data, dict):
                            app.logger.error("Data is not a dictionary")
                            return {"status_codes": {}, "home_links": {}, "other_links": {}}
                        
                        # **ENSURE ALL REQUIRED KEYS EXIST**
                        if "home_links" not in data:
                            data["home_links"] = {}
                        if "status_codes" not in data:
                            data["status_codes"] = {}
                        if "other_links" not in data:
                            data["other_links"] = {}
                        
                        # **LOG DATA SUMMARY**
                        home_links_count = len(data.get("home_links", {}))
                        status_codes_count = len(data.get("status_codes", {}))
                        other_links_count = len(data.get("other_links", {}))
                        
                        app.logger.info(f"Data contains {home_links_count} home links, {status_codes_count} status codes, {other_links_count} other links")
                        
                        return data
                        
                except json.JSONDecodeError as e:
                    app.logger.error(f"JSON decode error (attempt {attempt + 1}): {str(e)}")
                    if attempt == max_retries - 1:
                        # On final attempt, log file content for debugging
                        try:
                            with open(crawled_data, "r", encoding="utf-8") as file:
                                first_lines = file.read(500)
                                app.logger.error(f"First 500 chars of file: {first_lines}")
                        except:
                            pass
                        raise
                    else:
                        time.sleep(0.5)  # Wait before retry
                        
        except Exception as e:
            app.logger.error(f"Error reading {crawled_data}: {str(e)}")
    else:
        app.logger.warning(f"Data file does not exist: {crawled_data}")
    
    return {"status_codes": {}, "home_links": {}, "other_links": {}}

# Helper function to run async code in a thread
def run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

# Add this context processor to your app.py file (around line 1100, after other context processors)

@app.context_processor
def inject_website_settings():
    """Make website settings available to all templates"""
    try:
        website_settings = {
            'website_name': WebsiteSettings.get_setting('website_name', 'Web Analyzer Pro'),
            'website_icon': WebsiteSettings.get_setting('website_icon', 'fas fa-chart-line'),
            'website_logo_file': WebsiteSettings.get_setting('website_logo_file'),
            'website_tagline': WebsiteSettings.get_setting('website_tagline', 'Professional Web Analysis Tools')
        }
        return dict(website_settings=website_settings)
    except Exception as e:
        # Fallback to defaults if database is not available
        app.logger.error(f"Error loading website settings: {str(e)}")
        return dict(website_settings={
            'website_name': 'Web Analyzer Pro',
            'website_icon': 'fas fa-chart-line',
            'website_logo_file': None,
            'website_tagline': 'Professional Web Analysis Tools'
        })

# ----------------------
# Login Required Decorator
# ----------------------
from functools import wraps

def login_required(f):
    @wraps(f)  # Preserve function metadata
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap



# ----------------------
# Admin required decorator
#-----------------------
def admin_required(f):
    """
    Decorator to check if user is logged in as admin.
    If not, redirects to admin login page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if admin is logged in
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function
# ----------------------
# admin panel routes
# ----------------------
@app.route('/admin')
@admin_required
def admin_dashboard():
    now = datetime.now(UTC)
    # Get current page number from query params (default: 1)
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of payments per page
    
    class RecentPayment:
        def __init__(self, user, subscription, payment):  # ✅ Fixed: double underscores
            self.user = user
            self.subscription = subscription
            self.payment = payment

        def format_amount(self):
            try:
                return "{:,.2f}".format(self.payment.total_amount if hasattr(self.payment, 'total_amount') else self.payment.amount)
            except (AttributeError, TypeError):
                return "0.00"

    # Basic Stats - FIXED
    total_users = User.query.count()
    active_users = User.query.filter_by(email_confirmed=True).count()  # Users with confirmed emails
    unconfirmed_users = total_users - active_users
    
    # Active subscriptions - only count those that are active AND not expired
    active_subscriptions = SubscribedUser.query.filter(
        SubscribedUser.end_date > now,
        SubscribedUser._is_active == True
    ).count()
    
    # Expired subscriptions - those that have passed end_date
    expired_subscriptions = SubscribedUser.query.filter(
        SubscribedUser.end_date <= now
    ).count()

    # Revenue - ONLY FROM COMPLETED PAYMENTS
    thirty_days_ago = now - timedelta(days=30)
    total_revenue = db.session.query(func.sum(Payment.total_amount)).filter(
        Payment.status == 'completed'
    ).scalar() or 0
    
    monthly_revenue = db.session.query(func.sum(Payment.total_amount)).filter(
        Payment.status == 'completed',
        Payment.created_at >= thirty_days_ago
    ).scalar() or 0

    # Recent Payments - ONLY COMPLETED ONES
    recent_payments_query = (
        db.session.query(Payment, User, Subscription, InvoiceAddress)
        .join(User, Payment.user_id == User.id)
        .join(Subscription, Payment.subscription_id == Subscription.S_ID)
        .outerjoin(InvoiceAddress, Payment.iid == InvoiceAddress.payment_id)
        .filter(Payment.status == 'completed')  # ONLY COMPLETED
        .order_by(Payment.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )
    
    # ✅ Fixed: Create RecentPayment objects correctly
    recent_payments = [
        RecentPayment(user=user, subscription=subscription, payment=payment)
        for payment, user, subscription, invoice_address in recent_payments_query.items
    ]

    # Popular Plans - Convert to list of dicts
    popular_plans_query = (
        db.session.query(
            Subscription.plan,
            func.count(SubscribedUser.id).label('subscribers')
        )
        .join(SubscribedUser, Subscription.S_ID == SubscribedUser.S_ID)
        .filter(
            SubscribedUser.end_date > now,
            SubscribedUser._is_active == True
        )
        .group_by(Subscription.plan)
        .order_by(func.count(SubscribedUser.id).desc())
        .limit(3)
        .all()
    )
    popular_plans = [{"plan": row.plan, "subscribers": row.subscribers} for row in popular_plans_query]

    # Expiring Soon - ONLY ACTIVE SUBSCRIPTIONS
    seven_days_from_now = now + timedelta(days=7)
    expiring_soon = (
        db.session.query(User, Subscription, SubscribedUser)
        .join(SubscribedUser, User.id == SubscribedUser.U_ID)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(
            SubscribedUser.end_date > now,
            SubscribedUser.end_date <= seven_days_from_now,
            SubscribedUser._is_active == True  # ONLY ACTIVE
        )
        .all()
    )
    for user, subscription, subscribed_user in expiring_soon:
        if subscribed_user.end_date.tzinfo is None:
            subscribed_user.end_date = subscribed_user.end_date.replace(tzinfo=UTC)

    # Subscription Actions (30 days) — convert to list of dicts
    subscription_actions_query = (
        db.session.query(
            SubscriptionHistory.action,
            func.count(SubscriptionHistory.id).label('count')
        )
        .filter(SubscriptionHistory.created_at >= thirty_days_ago)
        .group_by(SubscriptionHistory.action)
        .all()
    )
    subscription_actions = [{"action": row.action, "count": row.count} for row in subscription_actions_query]

    # Auto-renewal stats - ONLY ACTIVE SUBSCRIPTIONS
    auto_renewal_count = SubscribedUser.query.filter(
        SubscribedUser.is_auto_renew == True,
        SubscribedUser.end_date > now,
        SubscribedUser._is_active == True
    ).count()
    
    non_renewal_count = SubscribedUser.query.filter(
        SubscribedUser.is_auto_renew == False,
        SubscribedUser.end_date > now,
        SubscribedUser._is_active == True
    ).count()

    # Payment Types — ONLY COMPLETED PAYMENTS
    payment_types_query = (
        db.session.query(
            Payment.payment_type,
            Payment.currency,
            func.count(Payment.iid).label('count'),
            func.sum(Payment.total_amount).label('total_revenue')
        )
        .filter(Payment.status == 'completed')  # ONLY COMPLETED
        .group_by(Payment.payment_type, Payment.currency)
        .all()
    )
    payment_types = [
        {
            "payment_type": row.payment_type,
            "currency": row.currency,
            "count": row.count,
            "total_revenue": row.total_revenue
        }
        for row in payment_types_query
    ]

    # Tax Breakdown - ONLY COMPLETED PAYMENTS
    tax_breakdown_query = (
        db.session.query(
            Payment.gst_rate,
            func.sum(Payment.gst_amount).label('total_tax'),
            func.count(Payment.iid).label('payment_count')
        )
        .filter(Payment.status == 'completed')  # ONLY COMPLETED
        .group_by(Payment.gst_rate)
        .all()
    )
    tax_breakdown = [
        {
            "gst_rate": row.gst_rate,
            "total_tax": row.total_tax,
            "payment_count": row.payment_count
        }
        for row in tax_breakdown_query
    ]
    
    # ✅ Fixed: Token Purchase Stats with correct field names
    token_stats_query = db.session.query(
        func.sum(TokenPurchase.token_count).label('total_tokens'),  # ✅ Fixed: token_count instead of tokens_purchased
        func.sum(TokenPurchase.total_amount).label('total_amount')
    ).filter(
        TokenPurchase.status == 'completed'  # ✅ Fixed: status instead of payment_status
    ).first()

    token_chart_data = {
        "tokens_purchased": token_stats_query.total_tokens or 0,
        "total_amount": token_stats_query.total_amount or 0
    }

    return render_template('admin/dashboard.html',
        now=now,
        total_users=total_users,
        active_users=active_users,
        unconfirmed_users=unconfirmed_users,
        active_subscriptions=active_subscriptions,
        expired_subscriptions=expired_subscriptions,
        recent_payments=recent_payments,
        total_revenue=total_revenue,
        monthly_revenue=monthly_revenue,
        popular_plans=popular_plans,
        token_chart_data=token_chart_data,
        expiring_soon=expiring_soon,
        subscription_actions=subscription_actions,
        auto_renewal_count=auto_renewal_count,
        non_renewal_count=non_renewal_count,
        payment_types=payment_types,
        recent_payments_pagination=recent_payments_query,
        tax_breakdown=tax_breakdown
    )
#-------------------------
# Admin login and logout
#-------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Input validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('admin/login.html')

        # ✅ NORMALIZE EMAIL TO LOWERCASE FOR CONSISTENT LOOKUP
        email = email.lower().strip()

        # ✅ USE CASE-INSENSITIVE QUERY
        admin = Admin.query.filter(
            func.lower(Admin.email_id) == email
        ).first()
        
        # Check if admin exists and has password set
        if not admin:
            flash('Invalid email or password.', 'danger')
            return render_template('admin/login.html')

        # Check if password hash exists
        if not admin.password_hash:
            flash('Password not set for this admin account.', 'danger')
            return render_template('admin/login.html')
            
        # Verify password
        try:
            if admin.check_password(password):
                session['admin_id'] = admin.id
                session['admin_name'] = admin.NAME
                session['email_id'] = admin.email_id
                # Store permissions as list
                session['admin_permissions'] = admin.permission if isinstance(admin.permission, list) else []
                
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                # This will trigger the popup modal
                flash('Invalid email or password.', 'danger')
                return render_template('admin/login.html')
        except Exception as e:
            app.logger.error(f"Password verification error: {str(e)}")
            flash('Error verifying password. Please contact administrator.', 'danger')
            return render_template('admin/login.html')

    return render_template('admin/login.html', email_id='')

@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))


# Route to add and display roles
@app.route('/admin/roles', methods=['GET', 'POST'])
@admin_required
def manage_roles():
    # Check if the user has permission to manage roles
    email_id = session.get('email_id')
    if not Admin.check_permission(email_id, 'manage_roles'):
        flash("You don't have permission to manage roles.", "danger")
        return redirect(url_for('admin_dashboard'))

        
    if request.method == 'POST':
        try:
            # Get form data and normalize email
            name = request.form.get('NAME')
            email_id = request.form.get('email_id')
            role = request.form.get('role')
            phone_number = request.form.get('phone_number')
            password = request.form.get('password')
            permissions = request.form.getlist('permissions[]')
            
            # ✅ NORMALIZE EMAIL TO LOWERCASE
            if email_id:
                email_id = email_id.lower().strip()
            
            # Validate required fields
            if not all([name, email_id, role]):
                flash('Name, email and role are required fields.', 'danger')
                return redirect(url_for('manage_roles'))

            # ✅ USE CASE-INSENSITIVE QUERY
            admin_role = Admin.query.filter(
                func.lower(Admin.email_id) == email_id
            ).first()

            if admin_role:
                # Update existing admin
                admin_role.NAME = name
                admin_role.email_id = email_id  # Store normalized email
                admin_role.role = role
                admin_role.phone_number = phone_number
                admin_role.permission = permissions
                admin_role.updated_at = datetime.now(UTC)
                
                 # Only update password if provided
                if password and password.strip():
                    if not admin_role.set_password(password):
                        flash('Error setting password.', 'danger')
                        return redirect(url_for('manage_roles'))
                
                flash(f'Role updated successfully for {name}!', 'success')
            else:
                # Create new admin
                if not password:
                    flash('Password is required for new admin roles.', 'danger')
                    return redirect(url_for('manage_roles'))

                new_role = Admin(
                    NAME=name,
                    email_id=email_id,  # Store normalized email
                    role=role,
                    phone_number=phone_number,
                    permission=permissions,
                    assigned_by=session.get('admin_name', 'System'),
                    is_active=True,
                    created_at=datetime.now(UTC)
                )

                # Set password for new admin
                if not new_role.set_password(password):
                    flash('Error setting password.', 'danger')
                    return redirect(url_for('manage_roles'))

                db.session.add(new_role)
                flash(f'New role created successfully for {name}!', 'success')

            db.session.commit()
            return redirect(url_for('manage_roles'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Role management error: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_roles'))

    roles = Admin.query.all()
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles/edit/<int:role_id>', methods=['GET', 'POST'])
@admin_required
def edit_role(role_id):
    role = Admin.query.get_or_404(role_id)

    if request.method == 'POST':
        try:
            # Get form data and normalize email
            role.NAME = request.form.get('NAME')
            email_id = request.form.get('email_id')
            role.role = request.form.get('role')
            role.phone_number = request.form.get('phone_number')
            permissions = request.form.getlist('permissions[]')
            password = request.form.get('password')

            # ✅ NORMALIZE EMAIL TO LOWERCASE
            if email_id:
                email_id = email_id.lower().strip()
                role.email_id = email_id

            # Validate required fields
            if not all([role.NAME, role.email_id, role.role]):
                flash('Name, email and role are required fields.', 'danger')
                return redirect(url_for('edit_role', role_id=role_id))

            # ✅ CHECK FOR DUPLICATE EMAIL (CASE-INSENSITIVE, EXCLUDING CURRENT ROLE)
            existing_admin = Admin.query.filter(
                func.lower(Admin.email_id) == email_id,
                Admin.id != role_id
            ).first()
            
            if existing_admin:
                flash('An admin with this email address already exists.', 'danger')
                return redirect(url_for('edit_role', role_id=role_id))

            # Update password if provided
            if password and password.strip():
                if not role.set_password(password):
                    flash('Error updating password.', 'danger')
                    return redirect(url_for('edit_role', role_id=role_id))

            # Update other fields
            role.permission = permissions
            role.updated_at = datetime.now(UTC)

            db.session.commit()
            flash(f'Role updated successfully for {role.NAME}!', 'success')
            return redirect(url_for('manage_roles'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Role update error: {str(e)}")
            flash(f'Error updating role: {str(e)}', 'danger')
            return redirect(url_for('edit_role', role_id=role_id))

    return render_template('admin/edit_role.html', 
                         role=role, 
                         role_permissions=role.permission if role.permission else [])

# Quick fix for the delete_role function without changing the database structure
# Replace the problematic line in your delete_role function

@app.route('/admin/roles/delete/<int:role_id>', methods=['POST'])
@admin_required
def delete_role(role_id):
    """Delete an admin role with proper validation"""
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'manage_roles'):
        flash("You don't have permission to delete roles.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    role = Admin.query.get_or_404(role_id)
    
    # Prevent self-deletion
    current_admin_id = session.get('admin_id')
    if role.id == current_admin_id:
        flash('You cannot delete your own role.', 'danger')
        return redirect(url_for('manage_roles'))
    
    # FIXED: Check if this is the last super admin using Python logic instead of SQL contains()
    role_has_manage_roles = False
    if role.permission and isinstance(role.permission, list):
        role_has_manage_roles = 'manage_roles' in role.permission
    
    if role_has_manage_roles:
        # Count other admins with manage_roles permission using Python filtering
        all_other_admins = Admin.query.filter(
            Admin.is_active == True,
            Admin.id != role_id
        ).all()
        
        super_admins_count = 0
        for admin in all_other_admins:
            if admin.permission and isinstance(admin.permission, list):
                if 'manage_roles' in admin.permission:
                    super_admins_count += 1
        
        if super_admins_count == 0:
            flash('Cannot delete the last admin with role management permissions.', 'warning')
            return redirect(url_for('manage_roles'))
    
    try:
        # Store role details for success message
        role_name = role.NAME
        role_email = role.email_id
        
        # Delete the role
        db.session.delete(role)
        db.session.commit()
        
        flash(f'Role for {role_name} ({role_email}) has been deleted successfully.', 'success')
        app.logger.info(f"Admin role deleted: {role_email} by {session.get('email_id')}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting role {role_id}: {str(e)}")
        flash(f'Error deleting role: {str(e)}', 'danger')
    
    return redirect(url_for('manage_roles'))


# Also update the Admin.check_permission method to avoid ARRAY.contains() issues
def updated_check_permission(email_id, required_permission):
    """Updated static method to check permissions by email without using SQL contains()"""
    admin = Admin.query.filter_by(email_id=email_id).first()
    if not admin:
        return False
        
    # For POST requests, check against form data
    if request.method == 'POST':
        form_email = request.form.get('email_id')
        if form_email == email_id:
            permissions = request.form.getlist('permissions[]')
            return required_permission in permissions
            
    # Otherwise check stored permissions using Python logic
    if admin.permission and isinstance(admin.permission, list):
        return required_permission in admin.permission
    
    return False

# Replace the existing check_permission method in your Admin class
Admin.check_permission = staticmethod(updated_check_permission)
#-----------------------
# Search History
#-----------------------
@app.route('/admin/search_history', methods=['GET'])
@admin_required
def admin_search_history():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'search_history'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get all filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    tool_filter = request.args.get('tool_filter', 'all')
    user_filter = request.args.get('user_filter', 'all')
    query_filter = request.args.get('query_filter')
    sort_by = request.args.get('sort_by', 'date_desc')
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Number of items per page
    
    # Base query to fetch all search histories
    query = SearchHistory.query
    
    # Apply date filters if provided
    if start_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(SearchHistory.created_at >= start_date_obj)
        except ValueError:
            flash("Invalid start date format. Please use YYYY-MM-DD.", "danger")
    
    if end_date:
        try:
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d')
            # Add one day to include the entire end date
            end_date_obj += timedelta(days=1)
            query = query.filter(SearchHistory.created_at < end_date_obj)
        except ValueError:
            flash("Invalid end date format. Please use YYYY-MM-DD.", "danger")
    
    # Apply tool filter if provided
    if tool_filter != 'all':
        query = query.filter(SearchHistory.usage_tool == tool_filter)
    
    # Apply user filter if provided
    if user_filter != 'all':
        query = query.filter(SearchHistory.u_id == user_filter)
    
    # Apply query filter if provided
    if query_filter:
        search_term = f"%{query_filter}%"
        query = query.filter(SearchHistory.search_history.like(search_term))
    
    # Apply sorting
    if sort_by == 'date_desc':
        query = query.order_by(SearchHistory.created_at.desc())
    elif sort_by == 'date_asc':
        query = query.order_by(SearchHistory.created_at.asc())
    elif sort_by == 'count_desc':
        query = query.order_by(SearchHistory.search_count.desc())
    elif sort_by == 'count_asc':
        query = query.order_by(SearchHistory.search_count.asc())
    
    # Calculate metrics for summary cards
    total_searches = db.session.query(db.func.sum(SearchHistory.search_count)).scalar() or 0
    active_users = db.session.query(db.func.count(db.distinct(SearchHistory.u_id))).scalar() or 0
    
    # Most popular tool
    popular_tool_query = db.session.query(
        SearchHistory.usage_tool, 
        db.func.sum(SearchHistory.search_count).label('total')
    ).group_by(SearchHistory.usage_tool).order_by(db.desc('total')).first()
    
    most_popular_tool = popular_tool_query[0] if popular_tool_query else "N/A"
    
    # Today's searches
    today = datetime.today().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    
    searches_today = db.session.query(
        db.func.sum(SearchHistory.search_count)
    ).filter(
        SearchHistory.created_at.between(today_start, today_end)
    ).scalar() or 0
    
    # Get available tools for dropdown
    available_tools = db.session.query(db.distinct(SearchHistory.usage_tool)).all()
    available_tools = [tool[0] for tool in available_tools]
    
    # Get available users for dropdown
    available_users = User.query.join(SearchHistory).distinct().all()
    
    # Paginate results
    paginated_history = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Fetch the most-used tool for each user
    user_most_used_tools = {}
    for entry in paginated_history.items:
        user_id = entry.u_id
        if user_id not in user_most_used_tools:
            # Fetch the most-used tool for the user
            tool_usage = db.session.query(SearchHistory.usage_tool, db.func.sum(SearchHistory.search_count))\
                .filter(SearchHistory.u_id == user_id)\
                .group_by(SearchHistory.usage_tool).all()
            if tool_usage:
                most_used_tool = max(tool_usage, key=lambda x: x[1])[0]  # Get the tool with the highest count
                user_most_used_tools[user_id] = most_used_tool
            else:
                user_most_used_tools[user_id] = "No tools used yet"
    
    # Pass the data to the template for rendering
    return render_template(
        'admin/search_history.html',
        history=paginated_history.items,
        pagination=paginated_history,
        user_most_used_tools=user_most_used_tools,
        start_date=start_date,
        end_date=end_date,
        tool_filter=tool_filter,
        user_filter=user_filter,
        query_filter=query_filter,
        sort_by=sort_by,
        available_tools=available_tools,
        available_users=available_users,
        total_searches=total_searches,
        active_users=active_users,
        most_popular_tool=most_popular_tool,
        searches_today=searches_today
    )


@app.route('/admin/search_history/export', methods=['GET'])
@admin_required
def admin_export_search_history():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'search_history'):
        flash("You don't have permission to access this feature.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get the same filter parameters as the main view
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    tool_filter = request.args.get('tool_filter', 'all')
    user_filter = request.args.get('user_filter', 'all')
    query_filter = request.args.get('query_filter')
    
    # Base query to fetch all search histories
    query = SearchHistory.query
    
    # Apply the same filters as the main view
    # ... (copy the filter code from admin_search_history)
    
    # Fetch all matching records
    all_history = query.all()
    
    # Create a CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['User ID', 'User Name', 'Tool', 'Search Query/URL', 'Count', 'Date & Time'])
    
    # Write data rows
    for entry in all_history:
        writer.writerow([
            entry.u_id,
            entry.user.name,
            entry.usage_tool,
            entry.search_history,
            entry.search_count,
            entry.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    # Prepare the response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'search_history_{datetime.now(UTC).strftime("%Y%m%d_%H%M%S")}.csv'
    )
#------------------------------
# admin Subscription Management
#------------------------------
@app.route('/admin/subscriptions')
@admin_required
def admin_subscriptions():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'subscription_management'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    # Get all subscription plans with subscriber counts
    subscriptions = (
        db.session.query(
            Subscription,
            func.count(SubscribedUser.id).label('active_subscribers'),
            func.sum(case(
                (SubscribedUser.end_date > datetime.now(UTC), 1),
                else_=0
            )).label('active_count')
        )
        .outerjoin(SubscribedUser, Subscription.S_ID == SubscribedUser.S_ID)
        .group_by(Subscription.S_ID)
        .all()
    )
    
    # Extract the Subscription object and other data into a list of dictionaries
    subscription_data = [
        {
            "subscription": row[0],  # Subscription object
            "active_subscribers": row[1],
            "active_count": row[2]
        }
        for row in subscriptions
    ]
    
    return render_template('admin/subscriptions.html', subscriptions=subscription_data)

@app.route('/admin/subscriptions/new', methods=['GET', 'POST'])
@admin_required
def admin_new_subscription():
    if request.method == 'POST':
        plan = request.form.get('plan')
        price = float(request.form.get('price'))
        days = int(request.form.get('days'))
        usage_per_day = int(request.form.get('usage_per_day'))
        tier = int(request.form.get('tier', 1))  # Added tier field
        features = request.form.get('features', '')  # Added features field
        
        # Validate inputs
        if not plan or price <= 0 or days <= 0 or usage_per_day <= 0 or tier <= 0:
            flash('Invalid subscription details. Please check your input.', 'danger')
            return redirect(url_for('admin_new_subscription'))
        
        # Check if plan name already exists
        existing_plan = Subscription.query.filter_by(plan=plan).first()
        if existing_plan:
            flash('A subscription plan with this name already exists.', 'danger')
            return redirect(url_for('admin_new_subscription'))
        
        new_subscription = Subscription(
            plan=plan,
            price=price,
            days=days,
            usage_per_day=usage_per_day,
            tier=tier,  # Added tier
            features=features  # Added features
        )
        
        db.session.add(new_subscription)
        db.session.commit()
        
        flash('Subscription plan created successfully!', 'success')
        return redirect(url_for('admin_subscriptions'))
    
    return render_template('admin/new_subscription.html')

@app.route('/admin/subscriptions/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Get active subscribers count
    active_subscribers = SubscribedUser.query.filter(
        SubscribedUser.S_ID == id,
        SubscribedUser.end_date > datetime.now(UTC)
    ).count()
    
    if request.method == 'POST':
        plan = request.form.get('plan')
        price = float(request.form.get('price'))
        days = int(request.form.get('days'))
        usage_per_day = int(request.form.get('usage_per_day'))
        tier = int(request.form.get('tier', subscription.tier))  # Added tier field
        features = request.form.get('features', subscription.features)  # Added features field
        
        # Validate inputs
        if not plan or price <= 0 or days <= 0 or usage_per_day <= 0 or tier <= 0:
            flash('Invalid subscription details. Please check your input.', 'danger')
            return redirect(url_for('admin_edit_subscription', id=id))
        
        # Check if plan name already exists with a different ID
        existing_plan = Subscription.query.filter(
            Subscription.plan == plan,
            Subscription.S_ID != id
        ).first()
        
        if existing_plan:
            flash('A subscription plan with this name already exists.', 'danger')
            return redirect(url_for('admin_edit_subscription', id=id))
        
        subscription.plan = plan
        subscription.price = price
        subscription.days = days
        subscription.usage_per_day = usage_per_day
        subscription.tier = tier  # Added tier
        subscription.features = features  # Added features
        
        db.session.commit()
        
        flash('Subscription plan updated successfully!', 'success')
        return redirect(url_for('admin_subscriptions'))
    
    return render_template('admin/edit_subscription.html', 
                          subscription=subscription,
                          active_subscribers=active_subscribers)

# Add these routes to your Flask application

@app.route('/admin/subscriptions/archive/<int:id>', methods=['POST'])
@admin_required
def admin_archive_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Check if already archived
    if subscription.archived_at:
        flash('This subscription plan is already archived.', 'warning')
        return redirect(url_for('admin_subscriptions'))
    
    # Archive the subscription plan
    subscription.is_active = False
    subscription.archived_at = datetime.now(UTC)
    db.session.commit()
    
    flash('Subscription plan has been archived successfully.', 'success')
    return redirect(url_for('admin_subscriptions'))


@app.route('/admin/subscriptions/restore/<int:id>', methods=['POST'])
@admin_required
def admin_restore_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Check if not archived
    if not subscription.archived_at:
        flash('This subscription plan is not archived.', 'warning')
        return redirect(url_for('admin_subscriptions'))
    
    # Restore the subscription plan
    subscription.is_active = True
    subscription.archived_at = None
    db.session.commit()
    
    flash('Subscription plan has been restored successfully.', 'success')
    return redirect(url_for('admin_subscriptions'))

@app.route('/admin/subscriptions/delete/<int:id>', methods=['POST'])
@admin_required
def admin_delete_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Check if there are any users subscribed to this plan (active or inactive)
    if subscription.subscribed_users:
        flash('Cannot delete subscription plan as it has users associated with it. Please remove the user subscriptions first.', 'danger')
        return redirect(url_for('admin_subscriptions'))
    
    # Check if there are any payments or history records associated with this plan
    payment_count = Payment.query.filter_by(subscription_id=id).count()
    history_count = SubscriptionHistory.query.filter(
        (SubscriptionHistory.S_ID == id) | 
        (SubscriptionHistory.previous_S_ID == id)
    ).count()
    
    if payment_count > 0 or history_count > 0:
        # Instead of blocking, mark as archived
        subscription.is_active = False
        subscription.archived_at = datetime.now(UTC)
        db.session.commit()
        
        flash('Subscription plan has been archived as it has payment or history records associated with it.', 'warning')
        return redirect(url_for('admin_subscriptions'))
    
    # If no constraints, perform actual deletion
    db.session.delete(subscription)
    db.session.commit()
    
    flash('Subscription plan deleted successfully!', 'success')
    return redirect(url_for('admin_subscriptions'))
    
@app.route('/admin/subscribed-users')
@admin_required
def admin_subscribed_users():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'subscribed_users_view'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    plan_filter = request.args.get('plan', 'all')
    
    # Get current time
    now = datetime.now(UTC)
    
    # Base query with joins
    query = (
        db.session.query(
            SubscribedUser, 
            User, 
            Subscription
        )
        .join(User, SubscribedUser.U_ID == User.id)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
    )
    
    # Apply filters based on status
    if status_filter == 'active':
        # Active: _is_active = True AND end_date > now
        query = query.filter(
            SubscribedUser._is_active == True,
            SubscribedUser.end_date > now
        )
    elif status_filter == 'cancelled':
        # Cancelled: _is_active = False AND end_date > now (cancelled by user)
        query = query.filter(
            SubscribedUser._is_active == False,
            SubscribedUser.end_date > now
        )
    elif status_filter == 'expired':
        # Expired: end_date <= now (naturally expired)
        query = query.filter(SubscribedUser.end_date <= now)
    
    if plan_filter != 'all':
        query = query.filter(Subscription.S_ID == plan_filter)
    
    # Get all subscription plans for the filter dropdown
    all_plans = Subscription.query.all()
    
    # Execute the query
    subscribed_users = query.order_by(SubscribedUser.end_date.desc()).all()
    
    # CALCULATE CORRECT STATISTICS
    # Total subscriptions (all subscription records)
    total_subscriptions = SubscribedUser.query.count()
    
    # Active subscriptions (active and not expired)
    active_subscriptions = SubscribedUser.query.filter(
        SubscribedUser._is_active == True,
        SubscribedUser.end_date > now
    ).count()
    
    # Expiring in 7 days (active subscriptions expiring within 7 days)
    seven_days_from_now = now + timedelta(days=7)
    expiring_soon_count = SubscribedUser.query.filter(
        SubscribedUser._is_active == True,
        SubscribedUser.end_date > now,
        SubscribedUser.end_date <= seven_days_from_now
    ).count()
    
    # Cancelled subscriptions (cancelled by user but not yet expired)
    cancelled_subscriptions = SubscribedUser.query.filter(
        SubscribedUser._is_active == False,
        SubscribedUser.end_date > now
    ).count()
    
    # Ensure timezone awareness
    for i, (sub_user, user, sub) in enumerate(subscribed_users):
        if sub_user.end_date.tzinfo is None:
            sub_user.end_date = sub_user.end_date.replace(tzinfo=UTC)
    
    # Define a function to check if a subscription is active
    def is_active(sub_user):
        return sub_user._is_active and sub_user.end_date > now
    
    return render_template('admin/subscribed_users.html', 
                          subscribed_users=subscribed_users,
                          all_plans=all_plans,
                          status_filter=status_filter,
                          plan_filter=plan_filter,
                          now=now,
                          is_active=is_active,
                          # Pass correct statistics
                          total_subscriptions=total_subscriptions,
                          active_subscriptions=active_subscriptions,
                          expiring_soon_count=expiring_soon_count,
                          cancelled_subscriptions=cancelled_subscriptions)

@app.route('/admin/subscribed-users/new', methods=['GET', 'POST'])
@admin_required
def admin_new_subscribed_user():
    if request.method == 'POST':
        user_id = int(request.form.get('user_id'))
        subscription_id = int(request.form.get('subscription_id'))
        auto_renew = request.form.get('auto_renew', 'off') == 'on'  # Added auto-renewal field
        
        # Check if user exists
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_new_subscribed_user'))
        
        # Check if subscription exists
        subscription = Subscription.query.get(subscription_id)
        if not subscription:
            flash('Subscription plan not found.', 'danger')
            return redirect(url_for('admin_new_subscribed_user'))
        
        # Check if user already has this subscription
        existing_sub = SubscribedUser.query.filter(
            SubscribedUser.U_ID == user_id,
            SubscribedUser.S_ID == subscription_id,
            SubscribedUser.end_date > datetime.now(UTC)
        ).first()
        
        if existing_sub:
            flash('User already has an active subscription to this plan.', 'warning')
            return redirect(url_for('admin_subscribed_users'))
        
        # Calculate dates
        start_date = datetime.now(UTC)
        end_date = start_date + timedelta(days=subscription.days)
        
        new_subscribed_user = SubscribedUser(
            U_ID=user_id,
            S_ID=subscription_id,
            start_date=start_date,
            end_date=end_date,
            current_usage=0,
            is_auto_renew=auto_renew  # Added auto-renewal
        )
        
        new_payment = Payment(
            base_amount=subscription.price,  # Changed from 'amount' to 'base_amount'
            user_id=user_id,
            subscription_id=subscription_id,
            razorpay_order_id=f"manual_admin_{int(time.time())}",
            razorpay_payment_id=f"manual_admin_{int(time.time())}",
            currency='INR',
            status='completed',
            payment_type='new',
            created_at=datetime.now(UTC)
        )
        
        # Add subscription history record
        new_history = SubscriptionHistory(
            U_ID=user_id,
            S_ID=subscription_id,
            action='new',
            created_at=datetime.now(UTC)
        )
        
        db.session.add(new_subscribed_user)
        db.session.add(new_payment)
        db.session.add(new_history)
        db.session.commit()
        
        flash('User subscription added successfully with payment record!', 'success')
        return redirect(url_for('admin_subscribed_users'))
    
    # Get all active users (email confirmed)
    users = User.query.filter_by(email_confirmed=True).all()
    
    # Get all subscription plans
    subscriptions = Subscription.query.all()
    
    return render_template('admin/new_subscribed_user.html', 
                          users=users, 
                          subscriptions=subscriptions)

@app.route('/admin/subscribed-users/reactivate/<int:id>', methods=['POST'])
@admin_required
def admin_reactivate_subscription(id):
    """Reactivate a cancelled subscription"""
    subscribed_user = SubscribedUser.query.get_or_404(id)
    
    # Check if subscription is actually cancelled and not expired
    if subscribed_user._is_active:
        flash('This subscription is already active.', 'warning')
        return redirect(url_for('admin_subscribed_users'))
    
    if subscribed_user.end_date <= datetime.now(UTC):
        flash('Cannot reactivate an expired subscription. Please create a new subscription.', 'danger')
        return redirect(url_for('admin_subscribed_users'))
    
    try:
        # Reactivate the subscription
        subscribed_user._is_active = True
        
        # Create a history record for reactivation
        history_record = SubscriptionHistory(
            U_ID=subscribed_user.U_ID,
            S_ID=subscribed_user.S_ID,
            action='reactivate',
            created_at=datetime.now(UTC)
        )
        
        db.session.add(history_record)
        db.session.commit()
        
        # Get user details for the flash message
        user = User.query.get(subscribed_user.U_ID)
        subscription = Subscription.query.get(subscribed_user.S_ID)
        
        flash(f'Subscription for {user.name} to {subscription.plan} plan has been reactivated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error reactivating subscription: {str(e)}")
        flash(f'Error reactivating subscription: {str(e)}', 'danger')
    
    return redirect(url_for('admin_subscribed_users'))

@app.route('/admin/subscribed-users/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_subscribed_user(id):
    # Fetch the subscribed user and related data
    subscribed_user = SubscribedUser.query.get_or_404(id)
    user = User.query.get(subscribed_user.U_ID)

    if request.method == 'POST':
        # Extract form data
        subscription_id = int(request.form.get('subscription_id'))
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        current_usage = int(request.form.get('current_usage', 0))
        auto_renew = request.form.get('auto_renew', 'off') == 'on'
        is_active = request.form.get('is_active', 'off') == 'on'  # Added is_active field

        # Validate the subscription plan exists
        subscription = Subscription.query.get(subscription_id)
        if not subscription:
            flash('Subscription plan not found.', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Check if start_date and end_date are provided
        if not start_date_str or not end_date_str:
            flash('Start date and End date are required.', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Parse dates
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').replace(tzinfo=UTC)
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(tzinfo=UTC)
            if end_date <= start_date:
                raise ValueError("End date must be after start date")
        except Exception as e:
            flash(f'Invalid date format: {str(e)}', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Validate current usage
        if current_usage < 0:
            flash('Current usage cannot be negative.', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Check if subscription has changed and record history
        old_subscription_id = subscribed_user.S_ID
        old_is_active = subscribed_user._is_active
        
        if old_subscription_id != subscription_id:
            action = 'upgrade' if subscription.tier > Subscription.query.get(old_subscription_id).tier else 'downgrade'

            # Create subscription history record
            history_record = SubscriptionHistory(
                U_ID=subscribed_user.U_ID,
                S_ID=subscription_id,
                action=action,
                previous_S_ID=old_subscription_id,
                created_at=datetime.now(UTC)
            )
            db.session.add(history_record)

        # Check if status changed from inactive to active or vice versa
        if old_is_active != is_active:
            action = 'reactivate' if is_active else 'admin_cancel'
            history_record = SubscriptionHistory(
                U_ID=subscribed_user.U_ID,
                S_ID=subscribed_user.S_ID,
                action=action,
                created_at=datetime.now(UTC)
            )
            db.session.add(history_record)

        # Update the subscribed user's details
        subscribed_user.S_ID = subscription_id
        subscribed_user.start_date = start_date
        subscribed_user.end_date = end_date
        subscribed_user.current_usage = current_usage
        subscribed_user.is_auto_renew = auto_renew
        subscribed_user._is_active = is_active  # Update active status

        db.session.commit()  # Commit the changes to the database

        flash('User subscription updated successfully!', 'success')
        return redirect(url_for('admin_subscribed_users'))

    # Fetch all subscriptions for the dropdown
    subscriptions = Subscription.query.all()
    return render_template('admin/edit_subscribed_user.html', 
                           subscribed_user=subscribed_user,
                           user=user,
                           subscriptions=subscriptions)

@app.route('/admin/subscribed-users/extend/<int:id>', methods=['POST'])
@admin_required
def admin_extend_subscription(id):
    subscribed_user = SubscribedUser.query.get_or_404(id)
    extension_days = int(request.form.get('extension_days', 0))
    
    if extension_days <= 0:
        flash('Extension days must be positive.', 'danger')
    elif not subscribed_user._is_active:
        flash('Cannot extend a cancelled subscription. Please reactivate it first.', 'warning')
    else:
        # Extend the subscription
        current_end_date = subscribed_user.end_date
        new_end_date = current_end_date + timedelta(days=extension_days)
        subscribed_user.end_date = new_end_date
        
        # Create a history record for this extension
        history_record = SubscriptionHistory(
            U_ID=subscribed_user.U_ID,
            S_ID=subscribed_user.S_ID,
            action='extend',
            created_at=datetime.now(UTC)
        )
        
        db.session.add(history_record)
        db.session.commit()
        flash(f'Subscription extended by {extension_days} days successfully!', 'success')
    
    return redirect(url_for('admin_subscribed_users'))

@app.route('/admin/subscribed-users/delete/<int:id>', methods=['POST'])
@admin_required
def admin_delete_subscribed_user(id):
    subscribed_user = SubscribedUser.query.get_or_404(id)
    
    # Get user details for the flash message
    user = User.query.get(subscribed_user.U_ID)
    subscription = Subscription.query.get(subscribed_user.S_ID)
    
    try:
        # Check if there are any usage logs associated with this subscription
        usage_logs = UsageLog.query.filter_by(subscription_id=id).all()
        
        if usage_logs:
            # Find if user has any other active subscription
            other_subscription = SubscribedUser.query.filter(
                SubscribedUser.U_ID == subscribed_user.U_ID,
                SubscribedUser.id != id,
                SubscribedUser.end_date > datetime.now(UTC)
            ).first()
            
            if other_subscription:
                # Reassign logs to that subscription
                for log in usage_logs:
                    log.subscription_id = other_subscription.id
                db.session.flush()  # Flush changes before deletion
            else:
                # Delete the usage logs since there's no other subscription
                for log in usage_logs:
                    db.session.delete(log)
                db.session.flush()  # Flush changes before deletion
        
        # Create a history record for deletion
        history_record = SubscriptionHistory(
            U_ID=subscribed_user.U_ID,
            S_ID=subscribed_user.S_ID,
            action='admin_delete',
            created_at=datetime.now(UTC)
        )
        
        db.session.add(history_record)
        db.session.delete(subscribed_user)
        db.session.commit()
        
        flash(f'Subscription for {user.name} to {subscription.plan} plan deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting subscription: {str(e)}', 'danger')
        app.logger.error(f"Error deleting subscription: {str(e)}")
    
    return redirect(url_for('admin_subscribed_users'))

# Add these helper functions at the top of your app.py file after imports
import re
from sqlalchemy import or_, func

def get_user_status_display(user):
    """Returns user account status (separate from subscription status)"""
    if user.email_confirmed:
        return ("Active", "bg-success", "fas fa-check-circle")
    else:
        return ("Unconfirmed", "bg-warning", "fas fa-exclamation-triangle")

def validate_user_data(name, email, password, user_id=None):
    """Validate user data and return list of errors"""
    errors = []
    
    # Name validation
    if not name:
        errors.append("Name is required.")
    elif len(name) < 2:
        errors.append("Name must be at least 2 characters long.")
    elif len(name) > 100:
        errors.append("Name cannot exceed 100 characters.")
    
    # Email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email:
        errors.append("Email is required.")
    elif not re.match(email_pattern, email):
        errors.append("Please enter a valid email address.")
    elif len(email) > 255:
        errors.append("Email address is too long.")
    else:
        # Check if email already exists (exclude current user if editing)
        query = User.query.filter(func.lower(User.company_email) == email.lower())
        if user_id:
            query = query.filter(User.id != user_id)
        existing_user = query.first()
        if existing_user:
            errors.append("A user with this email already exists.")
    
    # Password validation (only if password is provided)
    if password:
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        elif len(password) > 128:
            errors.append("Password cannot exceed 128 characters.")
        else:
            # Check password complexity
            password_errors = []
            if not re.search(r'[A-Z]', password):
                password_errors.append("one uppercase letter")
            if not re.search(r'[a-z]', password):
                password_errors.append("one lowercase letter")
            if not re.search(r'[0-9]', password):
                password_errors.append("one number")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                password_errors.append("one special character")
            
            if password_errors:
                errors.append(f"Password must contain at least {', '.join(password_errors)}.")
    
    return errors

# Complete Admin Users Route
# Fixed Admin Users Route
@app.route('/admin/users')
@admin_required
def admin_users():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'user_management'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Start with base query
    query = User.query
    
    # Apply filters based on USER status (not subscription status)
    if status_filter == 'active':
        query = query.filter_by(email_confirmed=True)
    elif status_filter == 'unconfirmed':
        query = query.filter_by(email_confirmed=False)
    elif status_filter == 'admin':
        query = query.filter_by(is_admin=True)
    
    # Apply search if provided
    if search_query:
        search_filter = or_(
            User.name.ilike(f'%{search_query}%'),
            User.company_email.ilike(f'%{search_query}%')
        )
        query = query.filter(search_filter)
    
    # Execute query with pagination
    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get subscription status for each user (separate from user account status)
    user_subscriptions = {}
    for user in pagination.items:
        active_sub = (
            db.session.query(SubscribedUser, Subscription)
            .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
            .filter(
                SubscribedUser.U_ID == user.id,
                SubscribedUser.end_date > datetime.now(UTC),
                SubscribedUser._is_active == True
            )
            .first()
        )
        user_subscriptions[user.id] = active_sub
    
    # Calculate user statistics (based on user account status, not subscription)
    total_users = User.query.count()
    active_users = User.query.filter_by(email_confirmed=True).count()
    unconfirmed_users = User.query.filter_by(email_confirmed=False).count()
    admin_users = User.query.filter_by(is_admin=True).count()
    
    # Calculate subscription statistics separately
    now = datetime.now(UTC)
    users_with_active_subscriptions = db.session.query(
        func.count(func.distinct(SubscribedUser.U_ID))
    ).filter(
        SubscribedUser.end_date > now,
        SubscribedUser._is_active == True
    ).scalar() or 0
    
    return render_template('admin/users.html', 
                           users=pagination.items,  # Pass users list
                           pagination=pagination,    # Pass pagination object
                           user_subscriptions=user_subscriptions,
                           status_filter=status_filter,
                           search_query=search_query,
                           # User account statistics
                           total_users=total_users,
                           active_users=active_users,
                           unconfirmed_users=unconfirmed_users,
                           admin_users=admin_users,
                           # Subscription statistics
                           users_with_active_subscriptions=users_with_active_subscriptions,
                           # Helper functions
                           get_user_status_display=get_user_status_display)

# Enhanced Add User Route with Validation
@app.route('/admin/add_user', methods=['POST'])
@admin_required
def admin_add_user():
    name = request.form.get('name', '').strip()
    company_email = request.form.get('company_email', '').lower().strip()
    password = request.form.get('password', '')
    email_confirmed = 'email_confirmed' in request.form
    is_admin = 'is_admin' in request.form
    
    # Validate input data
    errors = validate_user_data(name, company_email, password)
    if not password:
        errors.append("Password is required for new users.")
    
    # If there are validation errors, flash them and redirect
    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        # Create new user
        new_user = User(
            name=name,
            company_email=company_email,
            email_confirmed=email_confirmed,
            is_admin=is_admin,
            created_at=datetime.now(UTC)
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {name} ({company_email}) created successfully!', 'success')
        app.logger.info(f"Admin created new user: {company_email}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error creating user: {str(e)}")
        flash(f'Error creating user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

# Enhanced Edit User Route
@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    name = request.form.get('name', '').strip()
    email = request.form.get('company_email', '').lower().strip()
    email_confirmed = 'email_confirmed' in request.form
    is_admin = 'is_admin' in request.form
    password = request.form.get('password', '').strip()
    
    # Validate input data
    errors = validate_user_data(name, email, password, user_id)
    
    # If there are validation errors, flash them and redirect
    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        # Update user details
        user.name = name
        user.company_email = email
        user.email_confirmed = email_confirmed
        
        # Only update admin status if current user is not modifying themselves
        current_admin_id = session.get('admin_id')
        if user_id != current_admin_id:
            user.is_admin = is_admin
        else:
            if not is_admin:
                flash('You cannot remove your own admin privileges.', 'warning')
        
        # Update password if provided
        if password:
            user.set_password(password)
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        app.logger.info(f"Admin updated user: {user.company_email}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating user {user_id}: {str(e)}")
        flash(f'Error updating user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

# Delete User Route (Enhanced)
@app.route('/admin/remove_user/<int:user_id>', methods=['POST'])
@admin_required
def remove_user(user_id):
    """Remove a user and all associated data from the system."""
    user = User.query.get_or_404(user_id)
    
    # Prevent self-deletion
    current_admin_id = session.get('admin_id')
    if user_id == current_admin_id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Check if the user has active subscriptions
    active_subscription = SubscribedUser.query.filter(
        SubscribedUser.U_ID == user_id,
        SubscribedUser.end_date > datetime.now(UTC),
        SubscribedUser._is_active == True
    ).first()
    
    if active_subscription:
        flash('Cannot delete user with active subscriptions. Please cancel their subscriptions first.', 'warning')
        return redirect(url_for('admin_users'))
    
    # Store user details for the success message
    user_email = user.company_email
    user_name = user.name
    
    try:
        # Begin a transaction
        db.session.begin_nested()
        
        # Delete all related records in the correct order to avoid foreign key constraint violations
        
        # 1. Delete invoice addresses associated with the user's payments
        payment_ids = [p.iid for p in Payment.query.filter_by(user_id=user_id).all()]
        if payment_ids:
            InvoiceAddress.query.filter(InvoiceAddress.payment_id.in_(payment_ids)).delete(synchronize_session=False)
        
        # 2. Delete payments
        Payment.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        
        # 3. Delete search history
        SearchHistory.query.filter_by(u_id=user_id).delete(synchronize_session=False)
        
        # 4. Delete usage logs
        UsageLog.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        
        # 5. Delete subscription history
        SubscriptionHistory.query.filter_by(U_ID=user_id).delete(synchronize_session=False)
        
        # 6. Delete subscribed users
        SubscribedUser.query.filter_by(U_ID=user_id).delete(synchronize_session=False)
        
        # 7. Finally, delete the user
        db.session.delete(user)
        
        # Commit the transaction
        db.session.commit()
        
        app.logger.info(f"User {user_id} ({user_email}) successfully deleted by admin")
        flash(f'User {user_name} ({user_email}) removed successfully.', 'success')
        
    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        app.logger.error(f"Error deleting user {user_id}: {str(e)}")
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

# Reset User Password Route
@app.route('/admin/reset_user_password/<int:user_id>', methods=['POST'])
@admin_required
def admin_reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    
    # Generate a secure random password
    import secrets
    import string
    
    # Generate a 12-character password with mix of letters, numbers, and symbols
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    new_password = ''.join(secrets.choice(alphabet) for i in range(12))
    
    try:
        # Update the user's password
        user.set_password(new_password)
        db.session.commit()
        
        # In production, you should email this to the user instead of showing it
        flash(f'Password reset successfully! New password: {new_password}', 'success')
        app.logger.info(f"Admin reset password for user: {user.company_email}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resetting password for user {user_id}: {str(e)}")
        flash(f'Error resetting password: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

# User Details Route - COMPLETE UPDATED VERSION
@app.route('/admin/users/<int:user_id>')
@admin_required
def admin_user_details(user_id):
    user = User.query.get_or_404(user_id)
    
    # Get user's subscription history
    subscriptions = (
        db.session.query(SubscribedUser, Subscription)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(SubscribedUser.U_ID == user_id)
        .order_by(SubscribedUser.start_date.desc())
        .all()
    )
    
    # Get user's payment history
    payments = (
        db.session.query(Payment, Subscription)
        .join(Subscription, Payment.subscription_id == Subscription.S_ID)
        .filter(Payment.user_id == user_id)
        .order_by(Payment.created_at.desc())
        .all()
    )
    
    # Get user's search/usage history (recent)
    search_history = SearchHistory.query.filter_by(u_id=user_id)\
        .order_by(SearchHistory.created_at.desc())\
        .limit(10)\
        .all()
    
    # Calculate current date for checking subscription status - TIMEZONE AWARE
    now = datetime.now(UTC)
    
    # TIMEZONE FIX: Ensure all datetime objects are timezone-aware before template rendering
    
    # Fix user datetime fields
    if user.created_at and user.created_at.tzinfo is None:
        user.created_at = user.created_at.replace(tzinfo=UTC)
    
    # Fix subscription datetime fields
    for sub_user, subscription in subscriptions:
        # Ensure start_date is timezone-aware
        if sub_user.start_date and sub_user.start_date.tzinfo is None:
            sub_user.start_date = sub_user.start_date.replace(tzinfo=UTC)
        
        # Ensure end_date is timezone-aware
        if sub_user.end_date and sub_user.end_date.tzinfo is None:
            sub_user.end_date = sub_user.end_date.replace(tzinfo=UTC)
        
        # Also fix last_usage_reset if it exists
        if hasattr(sub_user, 'last_usage_reset') and sub_user.last_usage_reset and sub_user.last_usage_reset.tzinfo is None:
            sub_user.last_usage_reset = sub_user.last_usage_reset.replace(tzinfo=UTC)
    
    # Fix payment datetime fields
    for payment, subscription in payments:
        # Ensure payment created_at is timezone-aware
        if payment.created_at and payment.created_at.tzinfo is None:
            payment.created_at = payment.created_at.replace(tzinfo=UTC)
        
        # Ensure invoice_date is timezone-aware if it exists
        if hasattr(payment, 'invoice_date') and payment.invoice_date and payment.invoice_date.tzinfo is None:
            payment.invoice_date = payment.invoice_date.replace(tzinfo=UTC)
    
    # Fix search history datetime fields
    for search in search_history:
        # Ensure search created_at is timezone-aware
        if search.created_at and search.created_at.tzinfo is None:
            search.created_at = search.created_at.replace(tzinfo=UTC)
    
    # Import timezone for template use
    import datetime as dt_module
    
    return render_template('admin/user_details.html',
                          user=user,
                          subscriptions=subscriptions,
                          payments=payments,
                          search_history=search_history,
                          now=now,
                          timezone=dt_module.timezone)  # Make timezone available in template

@app.route('/admin/payments')
@admin_required
def admin_payments():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'payments'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    date_filter = request.args.get('date_range', '30')
    search_query = request.args.get('search', '')
    payment_type_filter = request.args.get('payment_type', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    now = datetime.now(UTC)
    
    # Build date filter
    date_ranges = {
        '7': now - timedelta(days=7),
        '30': now - timedelta(days=30),
        '90': now - timedelta(days=90),
        '180': now - timedelta(days=180),
        '365': now - timedelta(days=365)
    }
    date_threshold = date_ranges.get(date_filter, date_ranges['30'])
    
    # Import required SQLAlchemy functions
    from sqlalchemy import literal, cast, String, or_, func
    
    try:
        # Query subscription payments
        subscription_results = []
        if payment_type_filter in ['all', 'subscription']:
            sub_query = (
                db.session.query(
                    Payment.iid.label('payment_id'),
                    literal('subscription').label('payment_category'),
                    Payment.invoice_number,
                    Payment.razorpay_order_id,
                    Payment.razorpay_payment_id,
                    Payment.total_amount,
                    Payment.base_amount,
                    Payment.gst_amount,
                    Payment.status,
                    Payment.created_at,
                    Payment.payment_type,
                    Payment.user_id,
                    User.name.label('user_name'),
                    User.company_email,
                    Subscription.plan.label('description'),
                    literal(None).label('token_count')
                )
                .join(User, Payment.user_id == User.id)
                .join(Subscription, Payment.subscription_id == Subscription.S_ID)
            )
            
            # Apply filters to subscription query
            if status_filter != 'all':
                sub_query = sub_query.filter(Payment.status == status_filter)
            if date_filter in date_ranges:
                sub_query = sub_query.filter(Payment.created_at >= date_threshold)
            if search_query:
                sub_query = sub_query.filter(
                    or_(
                        User.name.ilike(f'%{search_query}%'),
                        User.company_email.ilike(f'%{search_query}%'),
                        Payment.invoice_number.ilike(f'%{search_query}%'),
                        Payment.razorpay_order_id.ilike(f'%{search_query}%')
                    )
                )
            
            subscription_results = sub_query.order_by(Payment.created_at.desc()).all()

        # Query token payments
        token_results = []
        if payment_type_filter in ['all', 'tokens']:
            token_query = (
                db.session.query(
                    TokenPurchase.id.label('payment_id'),
                    literal('tokens').label('payment_category'),
                    TokenPurchase.invoice_number,
                    TokenPurchase.razorpay_order_id,
                    TokenPurchase.razorpay_payment_id,
                    TokenPurchase.total_amount,
                    TokenPurchase.base_amount,
                    TokenPurchase.gst_amount,
                    TokenPurchase.status,
                    TokenPurchase.created_at,
                    literal('token_purchase').label('payment_type'),
                    TokenPurchase.user_id,
                    User.name.label('user_name'),
                    User.company_email,
                    cast(TokenPurchase.token_count, String).label('description'),
                    TokenPurchase.token_count
                )
                .join(User, TokenPurchase.user_id == User.id)
                .join(SubscribedUser, TokenPurchase.subscription_id == SubscribedUser.id)
            )
            
            # Apply filters to token query
            if status_filter != 'all':
                token_query = token_query.filter(TokenPurchase.status == status_filter)
            if date_filter in date_ranges:
                token_query = token_query.filter(TokenPurchase.created_at >= date_threshold)
            if search_query:
                token_query = token_query.filter(
                    or_(
                        User.name.ilike(f'%{search_query}%'),
                        User.company_email.ilike(f'%{search_query}%'),
                        TokenPurchase.invoice_number.ilike(f'%{search_query}%'),
                        TokenPurchase.razorpay_order_id.ilike(f'%{search_query}%')
                    )
                )
            
            token_results = token_query.order_by(TokenPurchase.created_at.desc()).all()

        # Combine results and sort by created_at
        all_results = list(subscription_results) + list(token_results)
        all_results.sort(key=lambda x: x.created_at or datetime.min.replace(tzinfo=UTC), reverse=True)
        
        # Calculate pagination
        total_count = len(all_results)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        payments_data = all_results[start_idx:end_idx]

    except Exception as e:
        app.logger.error(f"Error in payments query: {str(e)}")
        payments_data = []
        total_count = 0

    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    # Create pagination object-like structure
    class PaginationInfo:
        def __init__(self, items, page, per_page, total, has_prev, has_next, prev_num, next_num, pages):
            self.items = items
            self.page = page
            self.per_page = per_page
            self.total = total
            self.has_prev = has_prev
            self.has_next = has_next
            self.prev_num = prev_num if has_prev else None
            self.next_num = next_num if has_next else None
            self.pages = pages
            
        def iter_pages(self, left_edge=2, left_current=2, right_current=3, right_edge=2):
            last = self.pages
            for num in range(1, last + 1):
                if (num <= left_edge or 
                    (self.page - left_current - 1 < num < self.page + right_current) or 
                    num > last - right_edge):
                    yield num
    
    payments = PaginationInfo(
        items=payments_data,
        page=page,
        per_page=per_page,
        total=total_count,
        has_prev=has_prev,
        has_next=has_next,
        prev_num=page - 1,
        next_num=page + 1,
        pages=total_pages
    )
    
    # Calculate statistics - separate queries for accuracy
    subscription_stats = {
        'total_payments': Payment.query.count(),
        'total_revenue': db.session.query(func.sum(Payment.total_amount))
                            .filter(Payment.status == 'completed').scalar() or 0,
        'completed_payments': Payment.query.filter(Payment.status == 'completed').count()
    }
    
    token_stats = {
        'total_payments': TokenPurchase.query.count(),
        'total_revenue': db.session.query(func.sum(TokenPurchase.total_amount))
                            .filter(TokenPurchase.status == 'completed').scalar() or 0,
        'completed_payments': TokenPurchase.query.filter(TokenPurchase.status == 'completed').count()
    }
    
    # Combined stats
    stats = {
        'total_payments': subscription_stats['total_payments'] + token_stats['total_payments'],
        'total_revenue': subscription_stats['total_revenue'] + token_stats['total_revenue'],
        'completed_payments': subscription_stats['completed_payments'] + token_stats['completed_payments'],
        'subscription_stats': subscription_stats,
        'token_stats': token_stats,
        'payment_type_breakdown': {
            'subscription': subscription_stats['completed_payments'],
            'tokens': token_stats['completed_payments']
        }
    }
    
    # Revenue trend for chart - combined from both tables
    subscription_trend = (
        db.session.query(
            func.date_trunc('day', Payment.created_at).label('day'),
            func.sum(Payment.total_amount).label('total_revenue'),
            literal('subscription').label('type')
        )
        .filter(Payment.status == 'completed')
        .filter(Payment.created_at >= now - timedelta(days=30))
        .group_by('day')
        .all()
    )
    
    token_trend = (
        db.session.query(
            func.date_trunc('day', TokenPurchase.created_at).label('day'),
            func.sum(TokenPurchase.total_amount).label('total_revenue'),
            literal('tokens').label('type')
        )
        .filter(TokenPurchase.status == 'completed')
        .filter(TokenPurchase.created_at >= now - timedelta(days=30))
        .group_by('day')
        .all()
    )
    
    # Combine and aggregate revenue trends
    revenue_by_day = {}
    for trend in subscription_trend + token_trend:
        day = trend.day.date()
        if day not in revenue_by_day:
            revenue_by_day[day] = 0
        revenue_by_day[day] += trend.total_revenue
    
    # Convert to list format for template
    revenue_trend = [
        type('obj', (object,), {'day': day, 'total_revenue': revenue})()
        for day, revenue in sorted(revenue_by_day.items())
    ]
    
    return render_template('admin/payments.html',
                           payments=payments,
                           stats=stats,
                           revenue_trend=revenue_trend,
                           filters={
                               'status': status_filter,
                               'date_range': date_filter,
                               'search': search_query,
                               'payment_type': payment_type_filter
                           })

# Replace your existing admin_payment_details route with this updated version

@app.route('/admin/payments/<string:order_id>')
@admin_required
def admin_payment_details(order_id):
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'payments'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Determine payment type and get details
    payment_details = None
    payment_type = None
    
    # Try to find in subscription payments first (by invoice_number)
    subscription_payment = (
        db.session.query(Payment, User, Subscription, InvoiceAddress)
        .join(User, Payment.user_id == User.id)
        .join(Subscription, Payment.subscription_id == Subscription.S_ID)
        .outerjoin(InvoiceAddress, InvoiceAddress.payment_id == Payment.iid)
        .filter(Payment.invoice_number == order_id)
        .first()
    )
    
    if subscription_payment:
        payment_type = 'subscription'
        payment, user, subscription, invoice_address = subscription_payment
        payment_details = {
            'payment': payment,
            'user': user,
            'subscription': subscription,
            'invoice_address': invoice_address,
            'description': f"{subscription.plan} Subscription",
            'related_items': None
        }
    else:
        # Try to find in token purchases (by invoice_number)
        token_payment = (
            db.session.query(TokenPurchase, User, SubscribedUser, Subscription)
            .join(User, TokenPurchase.user_id == User.id)
            .join(SubscribedUser, TokenPurchase.subscription_id == SubscribedUser.id)
            .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
            .filter(TokenPurchase.invoice_number == order_id)
            .first()
        )
        
        if token_payment:
            payment_type = 'tokens'
            payment, user, subscribed_user, subscription = token_payment
            
            # Get related user tokens
            user_tokens = (
                UserToken.query
                .filter(UserToken.purchase_id == payment.id)
                .all()
            )
            
            payment_details = {
                'payment': payment,
                'user': user,
                'subscription': subscription,
                'subscribed_user': subscribed_user,
                'user_tokens': user_tokens,
                'description': f"{payment.token_count} Additional Tokens",
                'related_items': user_tokens
            }

    if not payment_details:
        flash(f"No payment found for Order ID: {order_id}", "danger")
        return redirect(url_for('admin_payments'))

    # Get Razorpay details if available
    razorpay_details = None
    payment_obj = payment_details['payment']
    
    if (payment_obj.razorpay_payment_id and 
        not payment_obj.razorpay_payment_id.startswith('manual_')):
        try:
            razorpay_details = razorpay_client.payment.fetch(payment_obj.razorpay_payment_id)
        except Exception as e:
            app.logger.warning(f"Razorpay fetch error: {str(e)}")

    # Get related payment history for this user
    user_id = payment_details['user'].id
    
    # Get both subscription and token payments for this user
    related_subscription_payments = (
        Payment.query
        .filter(Payment.user_id == user_id)
        .order_by(Payment.created_at.desc())
        .limit(5)
        .all()
    )
    
    related_token_payments = (
        TokenPurchase.query
        .filter(TokenPurchase.user_id == user_id)
        .order_by(TokenPurchase.created_at.desc())
        .limit(5)
        .all()
    )

    return render_template('admin/payment_details.html',
                           payment_details=payment_details,
                           payment_type=payment_type,
                           razorpay_details=razorpay_details,
                           related_subscription_payments=related_subscription_payments,
                           related_token_payments=related_token_payments)


# Add this new route for updating token payment status

@app.route('/admin/token_payments/update/<string:order_id>', methods=['POST'])
@admin_required
def admin_update_token_payment(order_id):
    """Update token payment status"""
    token_payment = TokenPurchase.query.filter_by(invoice_number=order_id).first_or_404()
    
    # Validate and update payment status
    new_status = request.form.get('status')
    valid_statuses = ['created', 'completed', 'failed', 'cancelled']
    
    if new_status in valid_statuses:
        old_status = token_payment.status
        token_payment.status = new_status
        
        try:
            if new_status == 'completed' and old_status != 'completed':
                # Generate invoice details if not exists
                if not token_payment.invoice_number:
                    token_payment._generate_invoice_details()
                
                # Create user tokens if they don't exist
                existing_user_token = UserToken.query.filter_by(purchase_id=token_payment.id).first()
                if not existing_user_token:
                    # Get the subscription
                    subscribed_user = SubscribedUser.query.get(token_payment.subscription_id)
                    
                    user_token = UserToken(
                        user_id=token_payment.user_id,
                        subscription_id=token_payment.subscription_id,
                        purchase_id=token_payment.id,
                        tokens_purchased=token_payment.token_count,
                        tokens_used=0,
                        tokens_remaining=token_payment.token_count,
                        expires_at=subscribed_user.end_date
                    )
                    db.session.add(user_token)
            
            db.session.commit()
            flash('Token payment status updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Token payment update error: {str(e)}")
            flash(f'Error updating token payment: {str(e)}', 'danger')
    else:
        flash('Invalid status', 'danger')
    
    return redirect(url_for('admin_payment_details', order_id=order_id))

@app.route('/admin/payments/update/<string:order_id>', methods=['POST'])
@admin_required
def admin_update_payment(order_id):
    payment = Payment.query.filter_by(invoice_number=order_id).first_or_404()
    
    # Validate and update payment status
    new_status = request.form.get('status')
    valid_statuses = ['created', 'completed', 'failed', 'cancelled']
    
    if new_status in valid_statuses:
        old_status = payment.status
        payment.status = new_status
        
        # Additional status change logic
        try:
            if new_status == 'completed' and old_status != 'completed':
                # Ensure invoice is generated
                if not payment.invoice_number:
                    payment.invoice_number = generate_unique_invoice_number()
                
                # Create or update subscription
                create_or_update_subscription(payment)
                
                # Generate invoice address if not exists
                create_invoice_address_for_payment(payment)
            
            db.session.commit()
            flash('Payment status updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Payment update error: {str(e)}")
            flash(f'Error updating payment: {str(e)}', 'danger')
    else:
        flash('Invalid status', 'danger')
    
    return redirect(url_for('admin_payment_details', order_id=order_id))

@app.route('/admin/payment/<order_id>/invoice')
@admin_required  
def admin_payment_invoice(order_id):
    """
    Generate and serve a PDF invoice for a specific payment order
    
    :param order_id: Razorpay order ID
    :return: PDF file response
    """
    # Find the payment by order_id
    payment = Payment.query.filter_by(razorpay_order_id=order_id).first_or_404()
    
    # Generate PDF invoice
    pdf_buffer = generate_invoice_pdf(payment)
    
    # Send the PDF as a download
    return send_file(
        pdf_buffer,
        download_name=f"invoice_{payment.invoice_number}.pdf",
        as_attachment=True,
        mimetype='application/pdf'
    )

def generate_unique_invoice_number():
    """
    Generate a unique invoice number
    """
    timestamp = datetime.now(UTC).strftime("%y%m%d")
    unique_id = str(uuid.uuid4().hex)[:8]
    return f"INV-{timestamp}-{unique_id}"

def create_or_update_subscription(payment):
    """
    Create or update subscription based on payment
    """
    # Check if subscription already exists
    existing_sub = SubscribedUser.query.filter_by(
        U_ID=payment.user_id,
        S_ID=payment.subscription_id
    ).first()
    
    if not existing_sub:
        subscription = Subscription.query.get(payment.subscription_id)
        start_date = datetime.now(UTC)
        end_date = start_date + timedelta(days=subscription.days)
        
        new_subscription = SubscribedUser(
            U_ID=payment.user_id,
            S_ID=payment.subscription_id,
            start_date=start_date,
            end_date=end_date,
            current_usage=0,
            is_auto_renew=True
        )
        
        # Record subscription history
        history_entry = SubscriptionHistory(
            U_ID=payment.user_id,
            S_ID=payment.subscription_id,
            action=payment.payment_type,
            previous_S_ID=payment.previous_subscription_id
        )
        
        db.session.add(new_subscription)
        db.session.add(history_entry)

def create_invoice_address_for_payment(payment):
    """
    Create invoice address for payment if not exists
    """
    existing_address = InvoiceAddress.query.filter_by(payment_id=payment.iid).first()
    
    if not existing_address:
        # Try to get user details
        user = User.query.get(payment.user_id)
        
        new_address = InvoiceAddress(
            payment_id=payment.iid,
            full_name=user.name,
            email=user.company_email,
            company_name=user.company_name if hasattr(user, 'company_name') else None,
            street_address=user.address if hasattr(user, 'address') else 'N/A',
            city=user.city if hasattr(user, 'city') else 'N/A',
            state=user.state if hasattr(user, 'state') else 'N/A',
            postal_code=user.postal_code if hasattr(user, 'postal_code') else 'N/A',
            gst_number=user.gst_number if hasattr(user, 'gst_number') else None
        )
        
        db.session.add(new_address)

@app.route('/admin/token/invoice/<string:invoice_number>')
@admin_required
def admin_token_invoice(invoice_number):
    # Get the token purchase by invoice number
    token_purchase = TokenPurchase.query.filter_by(invoice_number=invoice_number).first_or_404()
    user = User.query.get(token_purchase.user_id)
    subscription = SubscribedUser.query.get(token_purchase.subscription_id)

    # Render the invoice HTML
    rendered_html = render_template('admin/invoice_token.html', 
                                    token_purchase=token_purchase, 
                                    user=user, 
                                    subscription=subscription)

    # Convert HTML to PDF (you can use pdfkit or WeasyPrint)
    import pdfkit
    pdf = pdfkit.from_string(rendered_html, False)

    # Send as downloadable response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=Token-Invoice-{invoice_number}.pdf'
    return response


# Admin routes for contact submissions
@app.route('/admin/contact_submissions')
@admin_required
def admin_contact_submissions():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'contact_submissions'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    
    query = ContactSubmission.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    submissions = query.order_by(ContactSubmission.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Calculate stats
    total_count = ContactSubmission.query.count()
    new_count = ContactSubmission.query.filter_by(status='new').count()
    responded_count = ContactSubmission.query.filter_by(status='responded').count()
    
    # Today's submissions
    today = datetime.now(UTC).date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    today_count = ContactSubmission.query.filter(
        ContactSubmission.created_at.between(today_start, today_end)
    ).count()
    
    return render_template('admin/contact_submissions.html',
                          submissions=submissions,
                          status_filter=status_filter,
                          new_count=new_count,
                          responded_count=responded_count,
                          today_count=today_count)

@app.route('/admin/contact_submissions/<int:submission_id>')
@admin_required
def admin_contact_submission_detail(submission_id):
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'contact_submissions'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    submission = ContactSubmission.query.get_or_404(submission_id)
    
    # Mark as read if it was new
    if submission.status == 'new':
        submission.status = 'read'
        db.session.commit()
    
    return render_template('admin/contact_submission_detail.html', 
                          submission=submission)

@app.route('/admin/contact_submissions/<int:submission_id>/update', methods=['POST'])
@admin_required
def update_contact_submission(submission_id):
    submission = ContactSubmission.query.get_or_404(submission_id)
    
    new_status = request.form.get('status')
    admin_notes = request.form.get('admin_notes')
    
    if new_status in ['new', 'read', 'responded', 'spam']:
        submission.status = new_status
        if new_status == 'responded' and not submission.responded_at:
            submission.responded_at = datetime.now(UTC)
    
    if admin_notes is not None:  # Allow empty string
        submission.admin_notes = admin_notes
    
    db.session.commit()
    
    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': 'Submission updated successfully'})
    
    flash('Submission updated successfully!', 'success')
    return redirect(url_for('admin_contact_submission_detail', submission_id=submission_id))

@app.route('/admin/contact_submissions/<int:submission_id>/spam', methods=['POST'])
@admin_required
def mark_submission_as_spam(submission_id):
    submission = ContactSubmission.query.get_or_404(submission_id)
    submission.status = 'spam'
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Submission marked as spam'})

@app.route('/admin/contact_submissions/<int:submission_id>/delete', methods=['POST'])
@admin_required
def delete_contact_submission(submission_id):
    submission = ContactSubmission.query.get_or_404(submission_id)
    db.session.delete(submission)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Submission deleted successfully'})

@app.route('/admin/export_contact_submissions')
@admin_required
def admin_export_contact_submissions():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'contact_submissions'):
        flash("You don't have permission to access this feature.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    status_filter = request.args.get('status', 'all')
    
    query = ContactSubmission.query
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    submissions = query.order_by(ContactSubmission.created_at.desc()).all()
    
    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Name', 'Email', 'Message', 'Status', 'IP Address', 'Submitted Date', 'Admin Notes'])
    
    # Write data rows
    for submission in submissions:
        writer.writerow([
            submission.id,
            submission.name,
            submission.email,
            submission.message,
            submission.status,
            submission.ip_address or '',
            submission.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            submission.admin_notes or ''
        ])
    
    # Prepare response
    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'contact_submissions_{datetime.now(UTC).strftime("%Y%m%d_%H%M%S")}.csv'
    )

# Add these routes to your app.py file (around line 1800, with other admin routes)

import os
from werkzeug.utils import secure_filename

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico'}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin/website-settings')
@admin_required
def admin_website_settings():
    """Admin page to manage website settings"""
    email_id = session.get('email_id')
    
    # Check permission - you can add this to your permissions list
    if not Admin.check_permission(email_id, 'website_settings'):
        flash("You don't have permission to access website settings.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get all website settings
    settings = WebsiteSettings.query.all()
    settings_dict = {setting.setting_key: setting for setting in settings}
    
    # Get current values
    current_settings = {
        'website_name': WebsiteSettings.get_setting('website_name', 'Web Analyzer Pro'),
        'website_icon': WebsiteSettings.get_setting('website_icon', 'fas fa-chart-line'),
        'website_logo_file': WebsiteSettings.get_setting('website_logo_file'),
        'website_tagline': WebsiteSettings.get_setting('website_tagline', 'Professional Web Analysis Tools')
    }
    
    # Get list of FontAwesome icons for the dropdown
    fontawesome_icons = [
        {'class': 'fas fa-chart-line', 'name': 'Chart Line'},
        {'class': 'fas fa-analytics', 'name': 'Analytics'},
        {'class': 'fas fa-search', 'name': 'Search'},
        {'class': 'fas fa-globe', 'name': 'Globe'},
        {'class': 'fas fa-chart-bar', 'name': 'Chart Bar'},
        {'class': 'fas fa-chart-pie', 'name': 'Chart Pie'},
        {'class': 'fas fa-chart-area', 'name': 'Chart Area'},
        {'class': 'fas fa-sitemap', 'name': 'Sitemap'},
        {'class': 'fas fa-code', 'name': 'Code'},
        {'class': 'fas fa-desktop', 'name': 'Desktop'},
        {'class': 'fas fa-mobile-alt', 'name': 'Mobile'},
        {'class': 'fas fa-laptop', 'name': 'Laptop'},
        {'class': 'fas fa-cog', 'name': 'Settings'},
        {'class': 'fas fa-tools', 'name': 'Tools'},
        {'class': 'fas fa-wrench', 'name': 'Wrench'},
        {'class': 'fas fa-rocket', 'name': 'Rocket'},
        {'class': 'fas fa-star', 'name': 'Star'},
        {'class': 'fas fa-bolt', 'name': 'Bolt'},
        {'class': 'fas fa-fire', 'name': 'Fire'},
        {'class': 'fas fa-gem', 'name': 'Gem'}
    ]
    
    return render_template('admin/website_settings.html',
                          current_settings=current_settings,
                          settings_dict=settings_dict,
                          fontawesome_icons=fontawesome_icons)

@app.route('/admin/website-settings/update', methods=['POST'])
@admin_required
def admin_update_website_settings():
    """Update website settings"""
    email_id = session.get('email_id')
    admin_id = session.get('admin_id')
    
    # Check permission
    if not Admin.check_permission(email_id, 'website_settings'):
        flash("You don't have permission to update website settings.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Get form data
        website_name = request.form.get('website_name', '').strip()
        website_icon = request.form.get('website_icon', '').strip()
        website_tagline = request.form.get('website_tagline', '').strip()
        use_custom_logo = request.form.get('use_custom_logo') == 'on'
        
        # Validate required fields
        if not website_name:
            flash('Website name is required.', 'danger')
            return redirect(url_for('admin_website_settings'))
        
        # Handle logo file upload
        logo_filename = None
        if use_custom_logo and 'logo_file' in request.files:
            file = request.files['logo_file']
            if file and file.filename != '' and allowed_file(file.filename):
                # Secure the filename
                filename = secure_filename(file.filename)
                # Add timestamp to avoid conflicts
                timestamp = str(int(time.time()))
                name, ext = os.path.splitext(filename)
                logo_filename = f"logo_{timestamp}{ext}"
                
                # Save the file
                file_path = os.path.join(UPLOAD_FOLDER, logo_filename)
                file.save(file_path)
                
                # Delete old logo file if exists
                old_logo = WebsiteSettings.get_setting('website_logo_file')
                if old_logo:
                    old_file_path = os.path.join(UPLOAD_FOLDER, old_logo)
                    if os.path.exists(old_file_path):
                        try:
                            os.remove(old_file_path)
                        except:
                            pass  # Ignore if can't delete old file
        
        # Update settings in database
        WebsiteSettings.set_setting('website_name', website_name, admin_id, 'Website display name')
        WebsiteSettings.set_setting('website_icon', website_icon, admin_id, 'FontAwesome icon class')
        WebsiteSettings.set_setting('website_tagline', website_tagline, admin_id, 'Website tagline')
        
        # Update logo file setting
        if use_custom_logo and logo_filename:
            WebsiteSettings.set_setting('website_logo_file', logo_filename, admin_id, 'Custom logo file', 'file')
        elif not use_custom_logo:
            # Clear custom logo if not using it
            old_logo = WebsiteSettings.get_setting('website_logo_file')
            if old_logo:
                # Delete the file
                old_file_path = os.path.join(UPLOAD_FOLDER, old_logo)
                if os.path.exists(old_file_path):
                    try:
                        os.remove(old_file_path)
                    except:
                        pass
            WebsiteSettings.set_setting('website_logo_file', None, admin_id, 'Custom logo file cleared', 'file')
        
        flash('Website settings updated successfully!', 'success')
        app.logger.info(f"Website settings updated by admin {email_id}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating website settings: {str(e)}")
        flash(f'Error updating settings: {str(e)}', 'danger')
    
    return redirect(url_for('admin_website_settings'))

@app.route('/admin/website-settings/reset', methods=['POST'])
@admin_required
def admin_reset_website_settings():
    """Reset website settings to defaults"""
    email_id = session.get('email_id')
    admin_id = session.get('admin_id')
    
    # Check permission
    if not Admin.check_permission(email_id, 'website_settings'):
        flash("You don't have permission to reset website settings.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Delete custom logo file if exists
        old_logo = WebsiteSettings.get_setting('website_logo_file')
        if old_logo:
            old_file_path = os.path.join(UPLOAD_FOLDER, old_logo)
            if os.path.exists(old_file_path):
                try:
                    os.remove(old_file_path)
                except:
                    pass
        
        # Reset to default values
        WebsiteSettings.set_setting('website_name', 'Web Analyzer Pro', admin_id, 'Reset to default')
        WebsiteSettings.set_setting('website_icon', 'fas fa-chart-line', admin_id, 'Reset to default')
        WebsiteSettings.set_setting('website_tagline', 'Professional Web Analysis Tools', admin_id, 'Reset to default')
        WebsiteSettings.set_setting('website_logo_file', None, admin_id, 'Reset to default', 'file')
        
        flash('Website settings reset to defaults successfully!', 'success')
        app.logger.info(f"Website settings reset by admin {email_id}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resetting website settings: {str(e)}")
        flash(f'Error resetting settings: {str(e)}', 'danger')
    
    return redirect(url_for('admin_website_settings'))
# ----------------------
# Subscription Routes with Archive Handling
# ----------------------
# Replace your existing user_subscriptions route
@app.route('/subscriptions')
@login_required
@csrf_exempt
def user_subscriptions():
    user_id = session.get('user_id')
    if not user_id:
        flash("You need to log in first.", "warning")
        return redirect(url_for('login'))
    
    # Get current time
    now = datetime.now(UTC)
    
    # Get the most recent active subscription for the user
    active_subscription = None
    subscriptions = (
        db.session.query(SubscribedUser, Subscription)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > now)
        .filter(SubscribedUser._is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .order_by(SubscribedUser.start_date.desc())
        .all()
    )
    
    if len(subscriptions) > 1:
        active_subscription = subscriptions[0]
        for sub, plan in subscriptions[1:]:
            sub.is_active = False
            flash(f'Duplicate subscription "{plan.plan}" has been deactivated.', 'info')
        db.session.commit()
    elif len(subscriptions) == 1:
        active_subscription = subscriptions[0]
    
    # Ensure timezone awareness
    if active_subscription:
        sub, plan = active_subscription
        if sub.start_date and sub.start_date.tzinfo is None:
            sub.start_date = sub.start_date.replace(tzinfo=UTC)
        if sub.end_date and sub.end_date.tzinfo is None:
            sub.end_date = sub.end_date.replace(tzinfo=UTC)
    
    # Get payment history
    payment_history = Payment.query.filter_by(user_id=user_id).order_by(Payment.created_at.desc()).all()
    
    # Get available plans
    available_plans = (
        Subscription.query
        .filter(Subscription.is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .all()
    )
    
    # **IMPORTANT: Get token usage summary**
    usage_summary = get_user_token_summary(user_id)
    
    return render_template(
        'user/subscriptions.html',
        active_subscription=active_subscription,
        payment_history=payment_history,
        available_plans=available_plans,
        usage_summary=usage_summary,  # This was missing!
        now=now,
        hasattr=hasattr
    )

@app.route('/subscribe/<int:plan_id>', methods=['POST'])
@login_required
@csrf_exempt
def subscribe(plan_id):
    user_id = session.get('user_id')
    app.logger.info(f"Subscribe request received for plan {plan_id} by user {user_id}")

    # Check if user already has an active subscription
    now = datetime.now(UTC)
    active_subscription = SubscribedUser.query.filter(
        SubscribedUser.U_ID == user_id,
        SubscribedUser.end_date > now,
        SubscribedUser._is_active == True  # Using the underlying column name from your model
    ).first()
    
    if active_subscription:
        flash('You already have an active subscription. Please wait for it to expire or cancel it before subscribing to a new plan.', 'warning')
        return redirect(url_for('user_subscriptions'))

    # Get the subscription plan
    subscription = (
        Subscription.query
        .filter(Subscription.S_ID == plan_id)
        .filter(Subscription.is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .first_or_404()
    )
    
    # Create Razorpay order
    try:
        # Consistent GST calculation
        gst_rate = 0.18  # 18% GST
        base_amount = subscription.price
        gst_amount = base_amount * gst_rate
        total_amount = base_amount + gst_amount
        
        # Convert to paisa and round to integer
        amount_in_paisa = int(total_amount * 100)
        currency = 'INR'
        
        # Robust price validation
        if total_amount <= 0 or amount_in_paisa <= 0:
            app.logger.error(f'Invalid subscription price for plan {plan_id}')
            flash('Invalid subscription price. Please contact support.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Create Razorpay order
        razorpay_order = razorpay_client.order.create({
            'amount': amount_in_paisa,
            'currency': currency,
            'payment_capture': '1',
            'notes': {
                'user_id': user_id,
                'plan_id': plan_id,
                'description': f'Subscription for {subscription.plan}'
            }
        })
        
        # Store order details in the database with consistent calculations
        payment = Payment(
            base_amount=base_amount,
            gst_amount=gst_amount,
            total_amount=total_amount,
            user_id=user_id,
            subscription_id=plan_id,
            razorpay_order_id=razorpay_order['id'],
            currency=currency,
            status='created',
            payment_type='new',
            gst_rate=gst_rate
        )
        db.session.add(payment)
        db.session.commit()
        
        # Redirect to checkout page with Razorpay details
        return redirect(url_for('checkout', order_id=razorpay_order['id']))
        
    except Exception as e:
        app.logger.error(f"Error in subscribe route: {str(e)}", exc_info=True)
        db.session.rollback()
        flash(f'Error creating payment. Please try again or contact support.', 'danger')
        return redirect(url_for('user_subscriptions'))


# Optional: Add a validation method to Payment model
def validate_razorpay_order(subscription, amount, payment):
    """
    Validate Razorpay order details
    
    :param subscription: Subscription object
    :param amount: Amount in paisa
    :param payment: Payment object
    :return: Boolean indicating if order is valid
    """
    try:
        expected_amount = int(payment.total_amount * 100)
        return amount == expected_amount
    except Exception as e:
        app.logger.error(f"Order validation error: {str(e)}")
        return False


@app.route('/get_available_plans')
@login_required
@csrf_exempt
def get_available_plans():
    user_id = session.get('user_id')
    
    # Get current active subscription
    current_subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .filter(SubscribedUser._is_active == True)
        .first()
    )
    
    # Get query parameter to exclude current plan
    exclude_plan_id = request.args.get('exclude', type=int)
    
    # Get available plans
    available_plans = (
        Subscription.query
        .filter(Subscription.is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .filter(Subscription.S_ID != exclude_plan_id)
        .all()
    )
    
    # Convert to JSON
    plans_json = [
        {
            'S_ID': plan.S_ID,
            'plan': plan.plan,
            'price': plan.price,
            'days': plan.days,
            'tier': plan.tier
        } for plan in available_plans
    ]
    
    return jsonify(plans_json)



# Also update subscription_details route
@app.route('/subscription_details/<int:subscription_id>')
@login_required
@csrf_exempt
def subscription_details(subscription_id):
    user_id = session.get('user_id')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    try:
        # Get the SubscribedUser record
        subscribed_user = (
            SubscribedUser.query
            .filter(SubscribedUser.id == subscription_id)
            .filter(SubscribedUser.U_ID == user_id)
            .first()
        )
        
        if not subscribed_user:
            flash('Subscription not found.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Get the subscription plan details
        subscription_plan = (
            Subscription.query
            .filter(Subscription.S_ID == subscribed_user.S_ID)
            .first()
        )
        
        if not subscription_plan:
            flash('Subscription plan not found.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Get paginated usage history
        usage_query = (
            UsageLog.query
            .filter(UsageLog.subscription_id == subscription_id)
            .order_by(UsageLog.timestamp.desc())
        )
        
        usage_history = usage_query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Get payment records
        payment_records = (
            Payment.query
            .filter_by(user_id=user_id, subscription_id=subscribed_user.S_ID)
            .order_by(Payment.created_at.desc())
            .all()
        )
        
        # Calculate daily usage statistics
        daily_usage = {}
        all_usage = usage_query.limit(100).all()
        
        if all_usage:
            for usage in all_usage:
                date_key = usage.timestamp.strftime('%Y-%m-%d')
                if date_key not in daily_usage:
                    daily_usage[date_key] = 0
                daily_usage[date_key] += 1
        
        sorted_daily_usage = sorted(daily_usage.items(), key=lambda x: x[0], reverse=True)
        
        # Calculate days remaining
        now = datetime.now(UTC)
        if subscribed_user.end_date.tzinfo is None:
            subscribed_user.end_date = subscribed_user.end_date.replace(tzinfo=UTC)
        
        days_remaining = max(0, (subscribed_user.end_date - now).days)
        
        # Calculate usage percentage
        if subscription_plan.usage_per_day and subscription_plan.usage_per_day > 0:
            usage_percentage = min(100, (subscribed_user.current_usage / subscription_plan.usage_per_day) * 100)
        else:
            usage_percentage = 0
        
        # **IMPORTANT: Get token usage summary**
        usage_summary = get_user_token_summary(user_id)
        
        return render_template(
            'user/subscription_details.html',
            subscription=subscribed_user,
            plan=subscription_plan,
            usage_history=usage_history,
            payment_records=payment_records,
            daily_usage=sorted_daily_usage,
            days_remaining=days_remaining,
            usage_percentage=usage_percentage,
            usage_summary=usage_summary,  # This was missing!
            now=now
        )
        
    except Exception as e:
        app.logger.error(f"Error in subscription_details: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        flash('Error loading subscription details.', 'danger')
        return redirect(url_for('user_subscriptions'))


@app.route('/subscription/<int:subscription_id>/usage_history')
@login_required
@csrf_exempt
def get_usage_history(subscription_id):
    """AJAX endpoint to get paginated usage history"""
    user_id = session.get('user_id')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    try:
        # Verify the subscription belongs to the logged-in user
        subscribed_user = (
            SubscribedUser.query
            .filter(SubscribedUser.id == subscription_id)
            .filter(SubscribedUser.U_ID == user_id)
            .first()
        )
        
        if not subscribed_user:
            return "Subscription not found", 404
        
        # Get paginated usage history
        usage_history = (
            UsageLog.query
            .filter(UsageLog.subscription_id == subscription_id)
            .order_by(UsageLog.timestamp.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )
        
        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return render_template(
                'user/partials/usage_history.html',
                subscription=subscribed_user,
                usage_history=usage_history
            )
        
        # If not an AJAX request, redirect to the main page
        return redirect(url_for('subscription_details', subscription_id=subscription_id, page=page))
        
    except Exception as e:
        app.logger.error(f"Error in get_usage_history: {str(e)}")
        return "Error loading usage history", 500
    
def generate_invoice_pdf(payment):
    """
    Generate a modern, visually aesthetic PDF invoice for a specific payment
    
    :param payment: Payment model instance
    :return: BytesIO buffer containing the PDF
    """
    from io import BytesIO
    import os
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch, mm
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
    from num2words import num2words

    # Define brand colors to match the logo
    brand_color = colors.Color(0.73, 0.20, 0.04)  # Rust/orange color from logo
    secondary_color = colors.Color(0.95, 0.95, 0.95)  # Light gray for backgrounds
    text_color = colors.Color(0.25, 0.25, 0.25)  # Dark gray for text

    # Prepare buffer and document with reduced margins
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=A4, 
        leftMargin=12*mm, 
        rightMargin=12*mm, 
        topMargin=12*mm, 
        bottomMargin=12*mm
    )
    width, height = A4
    
    # Create custom styles
    brand_title_style = ParagraphStyle(
        name='BrandTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=brand_color,
        spaceAfter=3,
        alignment=TA_CENTER
    )
    
    company_name_style = ParagraphStyle(
        name='CompanyNameCustom',
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=text_color,
        spaceAfter=2
    )
    
    invoice_title_style = ParagraphStyle(
        name='InvoiceTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=16,
        alignment=TA_RIGHT,
        textColor=brand_color,
        spaceAfter=4
    )
    
    section_title_style = ParagraphStyle(
        name='SectionTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=text_color,
        spaceAfter=2
    )
    
    normal_style = ParagraphStyle(
        name='NormalCustom',
        fontName='Helvetica',
        fontSize=8,
        textColor=text_color,
        leading=10
    )
    
    right_aligned_style = ParagraphStyle(
        name='RightAlignedCustom',
        fontName='Helvetica',
        fontSize=9,
        alignment=TA_RIGHT,
        textColor=text_color
    )
    
    center_aligned_style = ParagraphStyle(
        name='CenterAlignedCustom',
        fontName='Helvetica',
        fontSize=9,
        alignment=TA_CENTER,
        textColor=text_color
    )

    # Prepare elements
    elements = []
    
    # Logo and Title side by side
    logo_path = os.path.join('assert', '4d-logo.webp')
    
    try:
        logo = Image(logo_path, width=1.5*inch, height=0.75*inch)
        header_data = [[
            logo, 
            Paragraph("TAX INVOICE", invoice_title_style)
        ]]
        
        header_table = Table(header_data, colWidths=[doc.width/2, doc.width/2])
        header_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(header_table)
    except:
        # Fallback if logo not found
        elements.append(Paragraph("TAX INVOICE", invoice_title_style))
    
    elements.append(Spacer(1, 5))
    
    # Company Details Section
    company_details = [
        [Paragraph("<b>Company Name:</b>", section_title_style)],
        [Paragraph("M/s. Fourth Dimension Media Solutions Pvt Ltd", normal_style)],
        [Paragraph("State & Code: Tamil Nadu (33)", normal_style)],
        [Paragraph("GSTIN: 33AABCF6993P1ZY", normal_style)],
        [Paragraph("PAN: AABCF6993P", normal_style)],
        [Paragraph("CIN: U22130TN2011PTC079276", normal_style)]
    ]
    
    company_table = Table(company_details, colWidths=[doc.width])
    company_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1)
    ]))
    elements.append(company_table)
    elements.append(Spacer(1, 5))
    
    # Bill To and Invoice Details Section (two columns)
    # Get customer details from payment object
    if payment.invoice_address:
        addr = payment.invoice_address
        bill_to_content = [
            [Paragraph("<b>Bill To,</b>", section_title_style)],
            [Paragraph(f"M/s. {addr.company_name or addr.full_name}", normal_style)],
            [Paragraph(f"{addr.street_address}", normal_style)],
            [Paragraph(f"{addr.city} - {addr.postal_code}", normal_style)],
            [Paragraph(f"{addr.state}, India", normal_style)],
            [Paragraph(f"GST No. {addr.gst_number or 'N/A'}", normal_style)],
            [Paragraph(f"PAN No. {addr.pan_number or 'N/A'}", normal_style)]
        ]
    else:
        user = payment.user
        bill_to_content = [
            [Paragraph("<b>Bill To,</b>", section_title_style)],
            [Paragraph(f"M/s. {user.name}", normal_style)],
            [Paragraph(f"Email: {user.company_email}", normal_style)]
        ]
    
    # Invoice details
    invoice_details_content = [
        [Paragraph(f"<b>Invoice No:</b> {payment.invoice_number}", normal_style)],
        [Paragraph(f"<b>Date:</b> {payment.invoice_date.strftime('%d/%m/%Y')}", normal_style)],
        [Spacer(1, 5)],
        [Paragraph(f"<b>Reverse Charge (Yes/No):</b> No", normal_style)],
        [Paragraph(f"<b>Place of supply:</b> Tamil Nadu (33)", normal_style)]
    ]
    
    # Create two-column layout for bill to and invoice details
    bill_invoice_data = [[
        Table(bill_to_content),
        Table(invoice_details_content)
    ]]
    
    bill_invoice_table = Table(bill_invoice_data, colWidths=[doc.width*0.6, doc.width*0.4])
    bill_invoice_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'LEFT')
    ]))
    elements.append(bill_invoice_table)
    elements.append(Spacer(1, 8))
    
    # Service Details Table
    # Table headers
    headers = ['Sl No', 'Description of Service', 'SAC/HSN', 'Qty', 'Rate', 'Amount (Rs)']
    
    # Calculate amounts
    base_amount = payment.base_amount
    cgst_rate = payment.gst_rate / 2
    sgst_rate = payment.gst_rate / 2
    cgst_amount = payment.gst_amount / 2
    sgst_amount = payment.gst_amount / 2
    total_amount = payment.total_amount
    
    # Build table data
    table_data = []
    table_data.append(headers)
    
    # Service row
    table_data.append([
        '1.',
        f'Digital Service - {payment.subscription.plan}',
        '998314',
        '1',
        f'{base_amount:.2f}',
        f'{base_amount:.2f}'
    ])
    
    # Totals
    table_data.append(['', '', '', '', 'Total', f'{base_amount:.2f}'])
    table_data.append(['', '', '', '', f'CGST @ {cgst_rate*100:.0f}%', f'{cgst_amount:.2f}'])
    table_data.append(['', '', '', '', f'SGST @ {sgst_rate*100:.0f}%', f'{sgst_amount:.2f}'])
    
    # Create service table
    col_widths = [doc.width*0.08, doc.width*0.35, doc.width*0.12, doc.width*0.08, doc.width*0.17, doc.width*0.2]
    service_table = Table(table_data, colWidths=col_widths)
    
    service_table.setStyle(TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), brand_color),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        
        # Data rows
        ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Sl No
        ('ALIGN', (1, 1), (1, -1), 'LEFT'),    # Description
        ('ALIGN', (2, 1), (2, -1), 'CENTER'),  # SAC/HSN
        ('ALIGN', (3, 1), (3, -1), 'CENTER'),  # Qty
        ('ALIGN', (4, 1), (4, -1), 'RIGHT'),   # Rate
        ('ALIGN', (5, 1), (5, -1), 'RIGHT'),   # Amount
        
        # Borders
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('TOPPADDING', (0, 1), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        
        # Total rows have special formatting
        ('FONTNAME', (4, 2), (5, -1), 'Helvetica-Bold'),
    ]))
    
    elements.append(service_table)
    
    # Total Invoice Value
    total_table_data = [
        ['Total Invoice Value', f'{total_amount:.2f}']
    ]
    
    total_table = Table(total_table_data, colWidths=[doc.width*0.8, doc.width*0.2])
    total_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), secondary_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), brand_color),
        ('ALIGN', (0, 0), (0, 0), 'RIGHT'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.grey),
        ('RIGHTPADDING', (1, 0), (1, 0), 10),
    ]))
    elements.append(total_table)
    elements.append(Spacer(1, 5))
    
    # Rupees in words
    amount_words = num2words(int(total_amount), lang='en_IN').title()
    words_data = [[f'Rupees in words: {amount_words} Rupees Only']]

    words_table = Table(words_data, colWidths=[doc.width])
    words_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(words_table)
    elements.append(Spacer(1, 15))
    
    # Signature area
    signature_data = [
        ['', 'For Fourth Dimension Media Solutions (P) Ltd'],
        ['', ''],
        ['', 'Authorised Signatory']
    ]
    
    signature_table = Table(signature_data, colWidths=[doc.width*0.6, doc.width*0.4])
    signature_table.setStyle(TableStyle([
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (1, 0), (1, -1), 9),
    ]))
    elements.append(signature_table)
    elements.append(Spacer(1, 15))
    
    # Terms & Conditions and Bank Details
    terms_conditions = [
        [Paragraph("<b>Terms & Condition</b>", section_title_style)],
        [Paragraph("• All disputes are subject to Chennai Jurisdiction only", normal_style)],
        [Paragraph('• Kindly Make all payments favoring "Fourth Dimension Media Solutions Pvt Ltd"', normal_style)],
        [Paragraph("• Payment terms: Immediate", normal_style)],
        [Paragraph("• Bank Name: City Union Bank., Tambaram West, Chennai -45", normal_style)],
        [Paragraph("  Account No: 512120020019966", normal_style)],
        [Paragraph("  Account Type: OD", normal_style)],
        [Paragraph("  IFSC Code: CIUB0000117", normal_style)]
    ]
    
    terms_table = Table(terms_conditions, colWidths=[doc.width])
    terms_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ('FONTSIZE', (0, 1), (-1, -1), 7),  # Smaller font for terms
    ]))
    elements.append(terms_table)
    
    # Build PDF
    doc.build(elements)
    
    # Reset buffer position
    buffer.seek(0)
    
    return buffer


# Example usage in a route
@app.route('/download_invoice/<int:payment_id>')
@login_required
@csrf_exempt
def download_invoice(payment_id):
    # Fetch the payment
    payment = Payment.query.get_or_404(payment_id)
    
    # Verify user authorization (optional but recommended)
    if payment.user_id != current_user.id:
        flash('Unauthorized access to invoice', 'error')
        return redirect(url_for('dashboard'))
    
    # Generate the invoice PDF
    pdf_buffer = generate_invoice_pdf(payment)
    
    # Send the PDF as a download
    return send_file(
        pdf_buffer,
        download_name=f"invoice_{payment.invoice_number}.pdf",
        as_attachment=True,
        mimetype='application/pdf'
    )
        
@app.route('/subscription/<int:subscription_id>')
@login_required

def view_subscription_details(subscription_id):
    subscription = SubscribedUser.query.get_or_404(subscription_id)
    
    # Verify this subscription belongs to the current user
    if subscription.U_ID != session.get('user_id'):
        flash('Unauthorized action', 'danger')
        return redirect(url_for('user_subscriptions'))
    
    # Get plan details
    plan = Subscription.query.get(subscription.S_ID)
    
    # Get payment history
    payments = Payment.query.filter_by(
        user_id=session.get('user_id'),
        subscription_id=subscription.S_ID
    ).order_by(Payment.created_at.desc()).all()
    
    return render_template('user/subscription_details.html', 
                          subscription=subscription, 
                          plan=plan,
                          payments=payments)
@app.route('/checkout/<order_id>', methods=['GET', 'POST'])
@login_required
@csrf_exempt
def checkout(order_id):
    user_id = session.get('user_id')
    
    # Get user details using get() method recommended for SQLAlchemy 2.0
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))
    
    # Get payment and subscription details
    payment = Payment.query.filter_by(razorpay_order_id=order_id, user_id=user_id).first()
    if not payment:
        flash('Payment not found', 'danger')
        return redirect(url_for('user_subscriptions'))
    
    # Use get() method for subscription
    subscription = db.session.get(Subscription, payment.subscription_id)
    if not subscription:
        flash('Subscription not found', 'danger')
        return redirect(url_for('user_subscriptions'))
    
    if request.method == 'POST':
        # Validate required fields
        required_fields = [
            'full_name', 'street_address', 'city', 
            'state', 'postal_code', 'country', 
            'email', 'phone_number'
        ]
        
        # Check if all required fields are filled
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in all required fields, especially {field.replace("_", " ")}', 'warning')
                return render_template('checkout.html', user=user, payment=payment, subscription=subscription)
        
        # Create or update invoice address
        invoice_address = InvoiceAddress(
            payment_id=payment.iid,
            full_name=request.form.get('full_name'),
            company_name=request.form.get('company_name', ''),
            street_address=request.form.get('street_address'),
            city=request.form.get('city'),
            state=request.form.get('state'),
            postal_code=request.form.get('postal_code'),
            country=request.form.get('country', 'India'),
            email=request.form.get('email', user.company_email),
            phone_number=request.form.get('phone_number'),
            gst_number=request.form.get('gst_number', ''),
            pan_number=request.form.get('pan_number', '')
        )
        
        db.session.add(invoice_address)
        db.session.commit()
        
        return redirect(url_for('verify_payment', order_id=order_id))
    
    return render_template(
        'user/checkout.html',
        user=user,
        payment=payment,
        subscription=subscription,
        base_amount=payment.base_amount,
        gst_rate=payment.gst_rate,
        gst_amount=payment.gst_amount,
        total_amount=payment.total_amount,
        razorpay_key_id=app.config['RAZORPAY_KEY_ID']
    )

# Update the verify_payment function in app.py (around line 2000)

@app.route('/payment/verify/<order_id>', methods=['GET', 'POST'])
@login_required
def verify_payment(order_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("You need to log in first.", "warning")
        return redirect(url_for('login'))
    
    # Get user details
    user = User.query.get_or_404(user_id)
    
    # Handle GET request - show payment verification page
    if request.method == 'GET':
        # Find pending payment for this order_id and user
        payment = Payment.query.filter_by(
            razorpay_order_id=order_id, 
            user_id=user_id, 
            status='created'
        ).first()
        
        if not payment:
            flash('No pending payment found for this order.', 'warning')
            return redirect(url_for('user_subscriptions'))
        
        # Load subscription details for display
        subscription = Subscription.query.get(payment.subscription_id)
        if not subscription:
            flash('Subscription not found.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Render verification page with all necessary data
        return render_template('payment/verify.html', 
                               payment=payment, 
                               subscription=subscription,
                               user=user,
                               razorpay_key_id=app.config['RAZORPAY_KEY_ID'])
    
    # Handle POST request - actual payment verification
    try:
        # Get payment details from Razorpay callback
        razorpay_payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = request.form.get('razorpay_order_id')
        razorpay_signature = request.form.get('razorpay_signature')
        
        # Validate input parameters
        if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature]):
            app.logger.error(f"Missing payment details for order: {order_id}")
            flash('Missing payment details. Please try again.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Find the payment record
        payment = Payment.query.filter_by(
            razorpay_order_id=razorpay_order_id, 
            user_id=user_id, 
            status='created'
        ).first()
        
        if not payment:
            app.logger.error(f"Payment record not found for order: {razorpay_order_id}, user: {user_id}")
            flash('Payment record not found.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Verify signature using custom method
        signature_valid = verify_razorpay_signature(
            razorpay_order_id, 
            razorpay_payment_id, 
            razorpay_signature, 
            app.config['RAZORPAY_KEY_SECRET']
        )
        
        if not signature_valid:
            app.logger.error(f"Signature verification failed for payment: {razorpay_payment_id}")
            flash('Payment verification failed. Please contact support.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Fetch payment details from Razorpay to verify amount
        try:
            payment_details = razorpay_client.payment.fetch(razorpay_payment_id)
            
            # Convert total_amount to paisa for comparison
            expected_amount_in_paisa = int(payment.total_amount * 100)
            
            # Verify the amount matches the expected amount
            if payment_details['amount'] != expected_amount_in_paisa:
                app.logger.error(
                    f"Amount mismatch: Expected {expected_amount_in_paisa}, "
                    f"Got {payment_details['amount']} for payment: {razorpay_payment_id}"
                )
                flash('Payment amount verification failed. Please contact support.', 'danger')
                return redirect(url_for('user_subscriptions'))
                
            # Verify payment is authorized/captured
            if payment_details['status'] not in ['authorized', 'captured']:
                app.logger.error(f"Payment not authorized: {payment_details['status']}")
                flash('Payment was not authorized. Please try again.', 'danger')
                return redirect(url_for('user_subscriptions'))
                
        except Exception as fetch_error:
            app.logger.error(f"Error fetching payment details from Razorpay: {str(fetch_error)}")
            flash('Unable to verify payment details with Razorpay.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Begin database transaction
        try:
            db.session.begin_nested()
            
            # Update payment details
            payment.razorpay_payment_id = razorpay_payment_id
            payment.status = 'completed'
            
            # Create new subscription (or update existing)
            subscription = Subscription.query.get(payment.subscription_id)
            
            # Calculate subscription dates
            start_date = datetime.now(UTC)
            end_date = start_date + timedelta(days=subscription.days)
            
            # Create new SubscribedUser record
            new_subscription = SubscribedUser(
                U_ID=user_id,
                S_ID=subscription.S_ID,
                start_date=start_date,
                end_date=end_date,
                is_auto_renew=True,  # Default to auto-renew
                current_usage=0,
                last_usage_reset=start_date,
                _is_active=True  # Set as active subscription
            )
            
            db.session.add(new_subscription)
            db.session.flush()  # Flush to get the new subscription ID
            
            # *** ADD THIS: REACTIVATE PAUSED TOKENS ***
            try:
                reactivated_count, total_tokens = reactivate_user_paused_tokens(user_id, new_subscription.id)
                if reactivated_count > 0:
                    app.logger.info(f"Reactivated {reactivated_count} token records ({total_tokens} tokens) for user {user_id}")
                    flash(f'Subscription activated! {total_tokens} previously unused tokens have been reactivated.', 'success')
                else:
                    flash(f'Payment successful! You are now subscribed to the {subscription.plan} plan.', 'success')
            except Exception as token_error:
                app.logger.error(f"Error reactivating tokens: {str(token_error)}")
                # Continue anyway - don't fail the payment for token reactivation issues
                flash(f'Payment successful! You are now subscribed to the {subscription.plan} plan.', 'success')
            
            # Add subscription history entry
            history_entry = SubscriptionHistory(
                U_ID=user_id,
                S_ID=subscription.S_ID,
                action=payment.payment_type,  # 'new', 'upgrade', etc.
                previous_S_ID=payment.previous_subscription_id,
                created_at=datetime.now(UTC)
            )
            db.session.add(history_entry)
            
            # Send confirmation email (optional)
            try:
                send_payment_confirmation_email(user, payment, subscription)
            except Exception as email_error:
                # Log but don't fail if email sending fails
                app.logger.error(f"Failed to send confirmation email: {str(email_error)}")
            
            # Commit all changes
            db.session.commit()
            
            app.logger.info(f"Payment successful: {razorpay_payment_id} for user: {user_id}")
            return redirect(url_for('user_subscriptions'))
            
        except Exception as db_error:
            # Roll back transaction on error
            db.session.rollback()
            app.logger.error(f"Database error during payment processing: {str(db_error)}")
            flash('Error processing payment. Please contact support.', 'danger')
            return redirect(url_for('user_subscriptions'))
    
    except Exception as e:
        # Catch-all for unexpected errors
        app.logger.error(f"Unexpected error in payment verification: {str(e)}", exc_info=True)
        flash('An unexpected error occurred. Please try again or contact support.', 'danger')
        return redirect(url_for('user_subscriptions'))

def verify_razorpay_signature(razorpay_order_id, razorpay_payment_id, razorpay_signature, razorpay_key_secret):
    """
    Verify Razorpay payment signature using HMAC SHA-256
    
    Args:
        razorpay_order_id (str): Order ID from Razorpay
        razorpay_payment_id (str): Payment ID from Razorpay
        razorpay_signature (str): Signature from Razorpay
        razorpay_key_secret (str): Razorpay key secret
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Create signature payload
        payload = f"{razorpay_order_id}|{razorpay_payment_id}"
        
        # Import hmac and hashlib for signature generation
        import hmac
        import hashlib
        
        # Generate expected signature
        generated_signature = hmac.new(
            razorpay_key_secret.encode('utf-8'), 
            payload.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(generated_signature, razorpay_signature)
    
    except Exception as e:
        app.logger.error(f"Signature verification error: {str(e)}")
        return False


def send_payment_confirmation_email(user, payment, subscription):
    """
    Send payment confirmation email to user
    
    Args:
        user (User): User model instance
        payment (Payment): Payment model instance
        subscription (Subscription): Subscription model instance
    """
    subject = f"Payment Confirmation - {subscription.plan} Subscription"
    
    # Calculate subscription end date
    start_date = datetime.now(UTC)
    end_date = start_date + timedelta(days=subscription.days)
    
    message = Message(
        subject,
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.company_email]
    )
    
    message.body = f"""Dear {user.name},

Thank you for your payment of {payment.total_amount} {payment.currency} for the {subscription.plan} subscription plan.

Payment Details:
- Order ID: {payment.razorpay_order_id}
- Payment ID: {payment.razorpay_payment_id}
- Invoice Number: {payment.invoice_number}
- Amount: {payment.total_amount} {payment.currency}
- Date: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC

Subscription Details:
- Plan: {subscription.plan}
- Start Date: {start_date.strftime('%Y-%m-%d')}
- End Date: {end_date.strftime('%Y-%m-%d')}
- Daily Usage Limit: {subscription.usage_per_day} operations

You can download your invoice from your account dashboard.

Thank you for choosing our service!

Best regards,
The Team
"""
    
    mail.send(message)
        
@app.route('/subscription/change/<int:new_plan_id>', methods=['GET', 'POST'])
@login_required
@csrf_exempt
def change_subscription(new_plan_id):
    user_id = session.get('user_id')
    
    # Extensive logging for debugging
    app.logger.info(f"Attempting to change subscription for user {user_id}")
    
    # Fetch all subscriptions for the user for detailed inspection
    all_subscriptions = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .all()
    )
    
    # Log details of all subscriptions
    for sub in all_subscriptions:
        app.logger.info(f"Subscription ID: {sub.id}")
        app.logger.info(f"Subscription Plan ID: {sub.S_ID}")
        app.logger.info(f"Start Date: {sub.start_date}")
        app.logger.info(f"End Date: {sub.end_date}")
        app.logger.info(f"Is Active (property): {sub.is_active}")
        app.logger.info(f"Is Active (column): {sub._is_active}")
        app.logger.info(f"Current Time (UTC): {datetime.now(UTC)}")
    
    # Get current active subscription with more detailed conditions
    current_subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .filter(
            # Check both the property and the column
            or_(
                SubscribedUser._is_active == True, 
                SubscribedUser.is_active == True
            )
        )
        .first()
    )
    
    # If no subscription found, log detailed information
    if not current_subscription:
        app.logger.warning(f"No active subscription found for user {user_id}")
        
        # Additional checks
        expired_subs = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date <= datetime.now(UTC))
            .all()
        )
        
        if expired_subs:
            app.logger.warning("Found expired subscriptions:")
            for sub in expired_subs:
                app.logger.warning(f"Subscription ID: {sub.id}, End Date: {sub.end_date}")
        
        flash('You don\'t have an active subscription to change.', 'warning')
        return redirect(url_for('user_subscriptions'))
    
    if not current_subscription:
        flash('You don\'t have an active subscription to change.', 'warning')
        return redirect(url_for('user_subscriptions'))
    
    # Get the new subscription plan
    new_plan = Subscription.query.get_or_404(new_plan_id)
    
    # Determine if this is an upgrade or downgrade
    is_upgrade = new_plan.tier > current_subscription.subscription.tier
    
    # Calculate remaining value of current subscription
    remaining_value = current_subscription.remaining_value()
    
    if request.method == 'POST':
        try:
            # Start a database transaction
            db.session.begin_nested()
            
            # Calculate the amount to charge with GST consideration
            if is_upgrade:
                # Amount to charge after applying remaining value credit
                amount_to_charge = max(0, new_plan.price - remaining_value)
                
                # Create a Payment instance 
                payment = Payment(
                    user_id=user_id,
                    subscription_id=new_plan_id,
                    base_amount=amount_to_charge,
                    payment_type='upgrade',
                    previous_subscription_id=current_subscription.S_ID,
                    credit_applied=remaining_value,
                    razorpay_order_id=None,  # Will be set later
                    status='created',
                    currency='INR'
                )
                
                # If there's an amount to charge, create Razorpay order
                if payment.total_amount > 0:
                    razorpay_order = razorpay_client.order.create({
                        'amount': int(payment.total_amount * 100),
                        'currency': 'INR',
                        'payment_capture': '1'
                    })
                    
                    payment.razorpay_order_id = razorpay_order['id']
                    db.session.add(payment)
                    db.session.commit()
                    
                    return redirect(url_for('checkout', order_id=razorpay_order['id']))
                else:
                    # No additional payment needed
                    _process_subscription_change(
                        user_id, 
                        current_subscription, 
                        new_plan_id, 
                        is_upgrade=True, 
                        credit_applied=remaining_value
                    )
                    
                    flash(f'Your subscription has been upgraded to {new_plan.plan}!', 'success')
                    return redirect(url_for('user_subscriptions'))
            
            else:
                # Downgrade case - process change without payment
                _process_subscription_change(
                    user_id, 
                    current_subscription, 
                    new_plan_id, 
                    is_upgrade=False, 
                    credit_applied=remaining_value
                )
                
                flash(f'Your subscription has been changed to {new_plan.plan}.', 'success')
                return redirect(url_for('user_subscriptions'))
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error processing subscription change: {str(e)}")
            flash(f'Error processing subscription change: {str(e)}', 'danger')
            return redirect(url_for('user_subscriptions'))
    
    # GET request - show confirmation page
    return render_template(
        'user/change_subscription.html',
        current_subscription=current_subscription,
        new_plan=new_plan,
        is_upgrade=is_upgrade,
        remaining_value=remaining_value,
        amount_to_charge=max(0, new_plan.price - remaining_value) if is_upgrade else 0,
        gst_rate=0.18  # Standard GST rate
    )

def change_subscription(new_plan_id):
    """
    Handle subscription change with improved logic for upgrades and downgrades
    
    Workflow:
    1. Validate current active subscription
    2. Get new subscription plan
    3. Determine if it's an upgrade or downgrade
    4. Calculate prorated credit/charge
    5. Process subscription change
    """
    user_id = session.get('user_id')

    # Validate current active subscription
    current_subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .filter(SubscribedUser.is_active == True)
        .first()
    )
    
    if not current_subscription:
        flash('You don\'t have an active subscription to change.', 'warning')
        return redirect(url_for('user_subscriptions'))
    
    # Get the new subscription plan
    new_plan = Subscription.query.get_or_404(new_plan_id)
    
    # Prevent changing to the same plan
    if current_subscription.S_ID == new_plan_id:
        flash('You are already on this plan.', 'info')
        return redirect(url_for('user_subscriptions'))
    
    # Determine upgrade or downgrade
    is_upgrade = new_plan.tier > current_subscription.subscription.tier
    
    # Calculate remaining subscription value
    remaining_days = (current_subscription.end_date - datetime.now(UTC)).days
    daily_rate_current = current_subscription.subscription.price / current_subscription.subscription.days
    remaining_value = daily_rate_current * remaining_days
    
    # Process the subscription change
    if request.method == 'POST':
        try:
            # Upgrade scenario
            if is_upgrade:
                # Calculate additional amount due
                amount_to_charge = max(0, new_plan.price - remaining_value)
                
                # Create payment record
                payment = Payment(
                    user_id=user_id,
                    subscription_id=new_plan_id,
                    base_amount=amount_to_charge,
                    payment_type='upgrade',
                    previous_subscription_id=current_subscription.S_ID,
                    credit_applied=remaining_value,
                    status='created',
                    currency='INR',
                    gst_rate=0.18  # Standard GST rate
                )
                
                # If there's an amount to charge, create Razorpay order
                if payment.total_amount > 0:
                    razorpay_order = razorpay_client.order.create({
                        'amount': int(payment.total_amount * 100),
                        'currency': 'INR',
                        'payment_capture': '1',
                        'notes': {
                            'user_id': user_id,
                            'plan_id': new_plan_id,
                            'action': 'upgrade'
                        }
                    })
                    
                    payment.razorpay_order_id = razorpay_order['id']
                    db.session.add(payment)
                    db.session.commit()
                    
                    return redirect(url_for('checkout', order_id=razorpay_order['id']))
                else:
                    # No additional payment needed
                    _process_subscription_change(
                        user_id, 
                        current_subscription, 
                        new_plan_id, 
                        is_upgrade=True, 
                        credit_applied=remaining_value
                    )
                    
                    flash(f'Your subscription has been upgraded to {new_plan.plan}!', 'success')
                    return redirect(url_for('user_subscriptions'))
            
            # Downgrade scenario
            else:
                # For downgrades, we might want to process immediately or pro-rate
                new_days = int(remaining_value / (new_plan.price / new_plan.days))
                
                _process_subscription_change(
                    user_id, 
                    current_subscription, 
                    new_plan_id, 
                    is_upgrade=False,
                    credit_applied=remaining_value,
                    additional_days=new_days
                )
                
                flash(f'Your subscription has been changed to {new_plan.plan}.', 'success')
                return redirect(url_for('user_subscriptions'))
                
        except Exception as e:
            app.logger.error(f"Error processing subscription change: {str(e)}")
            flash(f'Error processing subscription change: {str(e)}', 'danger')
            return redirect(url_for('user_subscriptions'))
    
    # GET request - show confirmation page
    return render_template(
        'user/change_subscription.html',
        current_subscription=current_subscription,
        new_plan=new_plan,
        is_upgrade=is_upgrade,
        remaining_value=remaining_value,
        amount_to_charge=max(0, new_plan.price - remaining_value) if is_upgrade else 0,
        remaining_days=remaining_days,
        gst_rate=0.18  # Standard GST rate
    )

def _process_subscription_change(user_id, current_subscription, new_plan_id, is_upgrade, credit_applied=0):
    """Process a subscription change (upgrade or downgrade)"""
    try:
        # Get the new subscription plan
        new_plan = Subscription.query.get(new_plan_id)
        
        # Deactivate current subscription
        current_subscription.is_active = False
        
        # Calculate new subscription dates
        start_date = datetime.now(UTC)
        
        if is_upgrade:
            # For upgrades, standard plan duration
            end_date = start_date + timedelta(days=new_plan.days)
        else:
            # For downgrades, calculate additional days from remaining credit
            new_plan_daily_price = new_plan.price / new_plan.days if new_plan.days > 0 else 0
            additional_days = int(credit_applied / new_plan_daily_price) if new_plan_daily_price > 0 else 0
            end_date = start_date + timedelta(days=new_plan.days + additional_days)
        
        # Create NEW active subscription
        new_subscription = SubscribedUser(
            U_ID=user_id,
            S_ID=new_plan_id,
            start_date=start_date,
            end_date=end_date,
            is_auto_renew=current_subscription.is_auto_renew,
            current_usage=0,
            last_usage_reset=start_date
        )
        
        # Add the new subscription
        db.session.add(new_subscription)
        
        # Log subscription change history
        history_entry = SubscriptionHistory(
            U_ID=user_id,
            S_ID=new_plan_id,
            action='upgrade' if is_upgrade else 'downgrade',
            previous_S_ID=current_subscription.S_ID,
            created_at=datetime.now(UTC)
        )
        db.session.add(history_entry)
        
        # Commit changes
        db.session.commit()
        
        return True
    
    except Exception as e:
        # Rollback in case of any errors
        db.session.rollback()
        app.logger.error(f"Subscription change error: {str(e)}")
        return False


# Add auto-renewal toggle route
@app.route('/subscription/auto-renew/<int:subscription_id>/<int:status>')
@login_required

def toggle_auto_renew(subscription_id, status):
    user_id = session.get('user_id')
    
    # Find the specific subscription
    subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.id == subscription_id)
        .filter(SubscribedUser.U_ID == user_id)
        .first_or_404()
    )
    
    # Update auto-renew status
    subscription.is_auto_renew = bool(status)
    db.session.commit()
    
    if subscription.is_auto_renew:
        flash('Auto-renewal has been enabled for your subscription.', 'success')
    else:
        flash('Auto-renewal has been disabled for your subscription.', 'info')
    
    return redirect(url_for('user_subscriptions'))


# Add a route to handle subscription cancellation
@app.route('/subscription/cancel/<int:subscription_id>', methods=['GET', 'POST'])
@login_required
@csrf_exempt
def cancel_subscription(subscription_id):
    user_id = session.get('user_id')
    
    # Find the specific subscription
    subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.id == subscription_id)
        .filter(SubscribedUser.U_ID == user_id)
        .first_or_404()
    )
    
    if request.method == 'POST':
        # Disable auto-renewal and set is_active to False
        subscription.is_auto_renew = False
        subscription.is_active = False
        
        # Add history entry
        history_entry = SubscriptionHistory(
            U_ID=user_id,
            S_ID=subscription.S_ID,
            action='cancel',
            previous_S_ID=subscription.S_ID,
            created_at=datetime.now(UTC)
        )
        db.session.add(history_entry)
        db.session.commit()
        
        flash('Your subscription has been cancelled. You can continue using it until the end date.', 'info')
        return redirect(url_for('user_subscriptions'))
    
    # GET request - show confirmation page
    return render_template(
        'user/cancel_subscription.html',
        subscription=subscription
    )

def has_active_subscription(user_id):
    """
    Strict check to ensure only ONE active subscription exists
    - Must be active
    - End date in the future
    - Exactly one active subscription
    """
    now = datetime.now(UTC)
    active_subs = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > now)
        .filter(SubscribedUser._is_active == True)
        .count()
    )
    
    return active_subs > 0  # Changed to check for at least one active subscription
def increment_usage_with_tokens(user_id, tokens_needed=1):
    """
    Enhanced usage increment that handles both daily quota and additional tokens
    Returns detailed information about what was used
    """
    try:
        # Get active subscription
        sub = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date > datetime.now(UTC))
            .filter(SubscribedUser._is_active == True)
            .first()
        )
        
        if not sub:
            return {
                'success': False, 
                'reason': 'no_active_subscription',
                'usage_breakdown': 'No active subscription found'
            }
        
        # Check if we need to reset the usage counter (new day)
        today = datetime.now(UTC).date()
        last_reset_date = getattr(sub, 'last_usage_reset', None)
        
        if not last_reset_date or last_reset_date.date() < today:
            # Reset counter for new day
            sub.current_usage = 0
            sub.last_usage_reset = datetime.now(UTC)
            app.logger.info(f"Daily usage reset for user {user_id}")
        
        daily_limit = sub.subscription.usage_per_day
        current_usage = sub.current_usage
        
        # Calculate how much we can use from daily quota
        daily_quota_available = max(0, daily_limit - current_usage)
        tokens_from_daily = min(tokens_needed, daily_quota_available)
        additional_tokens_needed = tokens_needed - tokens_from_daily
        
        app.logger.info(f"User {user_id}: Need {tokens_needed}, Daily available: {daily_quota_available}, Additional needed: {additional_tokens_needed}")
        
        # If we need additional tokens, check if they're available
        additional_tokens_used = 0
        if additional_tokens_needed > 0:
            # ✅ Changed: Get available additional tokens - only check expiration, not subscription match
            available_token_records = (
                UserToken.query
                .filter(UserToken.user_id == user_id)
                .filter(UserToken.tokens_remaining > 0)
                .filter(UserToken.expires_at > datetime.now(UTC))  # Only check if not expired (1 year limit)
                .order_by(UserToken.created_at.asc())  # Use oldest first
                .all()
            )
            
            total_additional_available = sum(record.tokens_remaining for record in available_token_records)
            app.logger.info(f"User {user_id}: Available additional tokens: {total_additional_available}")
            
            if total_additional_available < additional_tokens_needed:
                return {
                    'success': False,
                    'reason': 'no_tokens',
                    'usage_breakdown': f'Need {additional_tokens_needed} additional tokens, but only {total_additional_available} available',
                    'daily_used': current_usage,
                    'daily_limit': daily_limit,
                    'additional_available': total_additional_available
                }
            
            # Use additional tokens
            tokens_to_use = additional_tokens_needed
            for token_record in available_token_records:
                if tokens_to_use <= 0:
                    break
                
                tokens_from_this_record = min(tokens_to_use, token_record.tokens_remaining)
                token_record.tokens_used += tokens_from_this_record
                token_record.tokens_remaining -= tokens_from_this_record
                tokens_to_use -= tokens_from_this_record
                additional_tokens_used += tokens_from_this_record
                
                app.logger.info(f"Used {tokens_from_this_record} tokens from purchase {token_record.purchase_id}")
        
        # Update daily usage
        sub.current_usage += tokens_from_daily
        
        # Commit all changes
        db.session.commit()
        
        # Prepare usage breakdown message
        usage_parts = []
        if tokens_from_daily > 0:
            usage_parts.append(f"{tokens_from_daily} from daily quota")
        if additional_tokens_used > 0:
            usage_parts.append(f"{additional_tokens_used} additional tokens")
        
        usage_breakdown = f"Used {' + '.join(usage_parts)} (Total: {tokens_needed})"
        
        app.logger.info(f"User {user_id}: {usage_breakdown}")
        
        return {
            'success': True,
            'usage_breakdown': usage_breakdown,
            'tokens_from_daily': tokens_from_daily,
            'additional_tokens_used': additional_tokens_used,
            'new_daily_usage': sub.current_usage,
            'daily_limit': daily_limit
        }
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in increment_usage_with_tokens: {str(e)}")
        return {
            'success': False,
            'reason': 'system_error',
            'usage_breakdown': f'System error: {str(e)}'
        }
def pause_expired_subscription_tokens(subscription_id):
    """
    Pause tokens when a subscription expires
    Called when a subscription ends
    """
    try:
        # Get all active tokens for this subscription
        active_tokens = (
            UserToken.query
            .filter(UserToken.subscription_id == subscription_id)
            .filter(UserToken.tokens_remaining > 0)
            .filter(UserToken.is_paused == False)
            .all()
        )
        
        paused_count = 0
        for token in active_tokens:
            token.pause_tokens()
            paused_count += 1
        
        if paused_count > 0:
            db.session.commit()
            app.logger.info(f"Paused {paused_count} token records for expired subscription {subscription_id}")
        
        return paused_count
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error pausing tokens for subscription {subscription_id}: {str(e)}")
        return 0

def reactivate_user_paused_tokens(user_id, new_subscription_id):
    """
    Reactivate paused tokens when user gets new subscription
    Called when a new subscription is created
    """
    try:
        # Get all paused tokens for this user
        paused_tokens = (
            UserToken.query
            .filter(UserToken.user_id == user_id)
            .filter(UserToken.is_paused == True)
            .filter(UserToken.tokens_remaining > 0)
            .all()
        )
        
        reactivated_count = 0
        total_tokens_reactivated = 0
        
        for token in paused_tokens:
            token.reactivate_tokens(new_subscription_id)
            reactivated_count += 1
            total_tokens_reactivated += token.tokens_remaining
        
        if reactivated_count > 0:
            db.session.commit()
            app.logger.info(f"Reactivated {reactivated_count} token records ({total_tokens_reactivated} tokens) for user {user_id} with new subscription {new_subscription_id}")
        
        return reactivated_count, total_tokens_reactivated
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error reactivating tokens for user {user_id}: {str(e)}")
        return 0, 0    

# Keep the old function for backward compatibility, but make it use the new system
def increment_usage(user_id, tokens=1):
    """Backward compatibility wrapper"""
    result = increment_usage_with_tokens(user_id, tokens)
    return result['success']
def handle_expired_subscriptions():
    """
    Handle expired subscriptions and pause their unused tokens
    This should be called periodically (e.g., daily via cron job)
    """
    try:
        now = datetime.now(UTC)
        
        # Find subscriptions that just expired (within last 24 hours) and are still marked as active
        expired_subscriptions = (
            SubscribedUser.query
            .filter(SubscribedUser.end_date <= now)
            .filter(SubscribedUser.end_date >= now - timedelta(hours=24))
            .filter(SubscribedUser._is_active == True)
            .all()
        )
        
        total_paused_tokens = 0
        total_subscriptions_processed = 0
        
        for sub in expired_subscriptions:
            try:
                # Mark subscription as inactive
                sub._is_active = False
                
                # Pause unused tokens for this subscription
                paused_count = pause_expired_subscription_tokens(sub.id)
                total_paused_tokens += paused_count
                total_subscriptions_processed += 1
                
                # Add history entry
                history_entry = SubscriptionHistory(
                    U_ID=sub.U_ID,
                    S_ID=sub.S_ID,
                    action='expire',
                    created_at=now
                )
                db.session.add(history_entry)
                
                app.logger.info(f"Processed expired subscription {sub.id} for user {sub.U_ID}, paused {paused_count} token records")
                
            except Exception as e:
                app.logger.error(f"Error processing expired subscription {sub.id}: {str(e)}")
        
        if total_subscriptions_processed > 0:
            db.session.commit()
            app.logger.info(f"Processed {total_subscriptions_processed} expired subscriptions, paused {total_paused_tokens} token records")
        
        return total_subscriptions_processed, total_paused_tokens
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error handling expired subscriptions: {str(e)}")
        return 0, 0

# Update the existing process_auto_renewals function to include token pausing
def process_auto_renewals():
    """Process auto-renewals for expiring subscriptions and handle token pausing"""
    # Get subscriptions expiring in the next 24 hours with auto-renew enabled
    now = datetime.now(UTC)
    expiring_soon = (
        SubscribedUser.query
        .filter(SubscribedUser.is_auto_renew == True)
        .filter(SubscribedUser._is_active == True)  # Only active subscriptions
        .filter(SubscribedUser.end_date <= now + timedelta(days=1))
        .filter(SubscribedUser.end_date > now)
        .options(joinedload(SubscribedUser.subscription))
        .all()
    )
    
    for sub in expiring_soon:
        try:
            # Process auto-renewal (existing logic)
            subscription = sub.subscription
            
            # Create Razorpay order for renewal
            payment = Payment(
                base_amount=subscription.price,
                user_id=sub.U_ID,
                subscription_id=sub.S_ID,
                razorpay_order_id=None,  # Will be set by Razorpay
                status='created',
                payment_type='renewal'
            )
            
            # Create Razorpay order
            razorpay_order = razorpay_client.order.create({
                'amount': int(payment.total_amount * 100),
                'currency': 'INR',
                'payment_capture': '1'
            })
            
            # Update with Razorpay order ID
            payment.razorpay_order_id = razorpay_order['id']
            db.session.add(payment)
            db.session.commit()
            
            # Send email notification to user about upcoming renewal
            # (implementation depends on your email system)
            
        except Exception as e:
            app.logger.error(f"Auto-renewal failed for user {sub.U_ID}: {str(e)}")
    
    # Handle expired subscriptions and pause tokens
    try:
        handle_expired_subscriptions()
    except Exception as e:
        app.logger.error(f"Error handling expired subscriptions in auto-renewal process: {str(e)}")
    
    db.session.commit()

def record_usage_log(user_id, subscription_id, operation_type, details=None, tokens_used=1):
    """
    Record a usage log entry for a subscription with token cost
    
    Args:
        user_id (int): ID of the user
        subscription_id (int): ID of the SubscribedUser record
        operation_type (str): Type of operation performed
        details (str, optional): Additional details about the operation
        tokens_used (int): Number of tokens consumed (default: 1)
    
    Returns:
        bool: True if recording succeeded, False otherwise
    """
    try:
        # Include token cost in details if not already specified
        if details and "tokens" not in details.lower():
            details = f"{details} - Tokens used: {tokens_used}"
        elif not details:
            details = f"Tokens used: {tokens_used}"
        
        # Create new usage log entry
        usage_log = UsageLog(
            user_id=user_id,
            subscription_id=subscription_id,
            operation_type=operation_type,
            details=details,
            timestamp=datetime.now(UTC)
        )
        
        db.session.add(usage_log)
        db.session.commit()
        return True
        
    except Exception as e:
        app.logger.error(f"Error recording usage log: {str(e)}")
        db.session.rollback()
        return False

def subscription_required_with_tokens(tokens=1):
    """
    Decorator that checks subscription and uses tokens (daily quota + additional tokens)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is logged in
            if not current_user.is_authenticated:
                if 'user_id' not in session:
                    flash("Please login to access this feature.", "warning")
                    return redirect(url_for('login'))
                user_id = session.get('user_id')
            else:
                user_id = current_user.id
            
            # Check if user has active subscription
            now = datetime.now(UTC)
            active_subscription = (
                SubscribedUser.query
                .filter(SubscribedUser.U_ID == user_id)
                .filter(SubscribedUser.end_date > now)
                .filter(SubscribedUser._is_active == True)
                .first()
            )
            
            if not active_subscription:
                flash("Please subscribe to access this feature.", "warning")
                return redirect(url_for('user_subscriptions'))
            
            # Try to increment usage (this will handle both daily quota and additional tokens)
            usage_result = increment_usage_with_tokens(user_id, tokens)
            
            if not usage_result['success']:
                if usage_result['reason'] == 'no_tokens':
                    flash(f"You've reached your daily limit and don't have enough additional tokens. This action requires {tokens} tokens.", "warning")
                    return redirect(url_for('user_subscriptions'))
                else:
                    flash(f"Unable to process request: {usage_result['reason']}", "warning")
                    return redirect(url_for('user_subscriptions'))
            
            # Record usage log with detailed token information
            record_usage_log(
                user_id=user_id,
                subscription_id=active_subscription.id,
                operation_type=f.__name__,
                details=f"Operation completed - {usage_result['usage_breakdown']}"
            )
            
            # Show token usage notification if additional tokens were used
            if usage_result.get('additional_tokens_used', 0) > 0:
                flash(f"Daily limit reached. Used {usage_result['additional_tokens_used']} additional tokens.", "info")
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def subscription_check_only(f):
    """
    Decorator that checks if user has active subscription but doesn't count usage.
    Use this for pages that should be accessible to subscribers without consuming daily quota.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is logged in
        if not current_user.is_authenticated:
            if 'user_id' not in session:
                flash("Please login to access this feature.", "warning")
                return redirect(url_for('login'))
            user_id = session.get('user_id')
        else:
            user_id = current_user.id
        
        # Check subscription without incrementing usage
        now = datetime.now(UTC)
        active_subscription = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date > now)
            .filter(SubscribedUser._is_active == True)
            .first()
        )
        
        if not active_subscription:
            flash("Please subscribe to access this feature.", "warning")
            return redirect(url_for('user_subscriptions'))
        
        # No usage increment - just allow access
        return f(*args, **kwargs)
    
    return decorated_function
# ---------------------------------------
# user login signup and reset password
# ---------------------------------------
from datetime import datetime

@app.route('/')
def landing():
    """Landing page route that doesn't require login"""
    current_year = datetime.now().year
    return render_template('landing.html', current_year=current_year)



@app.route('/dashboard', methods=['GET'])
@login_required
def index():
    # Get the user_id from session if user is logged in
    user_id = session.get('user_id')
    view_mode = "dashboard"  # Default to dashboard view
    
    # Initialize data
    recent_analyses = []
    today_token_usage = 0
    total_token_usage = 0
    top_operation_type = "N/A"
    weekly_trend = 0
    today_vs_yesterday = 0
    user_name = "User"
    tool_distribution = []
    milestone_progress = 0
    has_active_subscription = False
    recent_activity = {}
    available_tokens = 0
    total_daily_tokens = 0
    token_usage_percentage = 0
    
    # Only fetch data if a user is logged in
    if user_id:
        # Get the user's name from the database
        user = User.query.get(user_id)
        if user:
            user_name = user.name
            recent_activity = {
                'last_login': user.get_last_login_display(),
                'profile_updated': user.get_profile_updated_display(),
                'password_changed': user.get_password_changed_display()
            }
        
        # Get time ranges
        today = date.today()
        yesterday = today - timedelta(days=1)
        week_ago = today - timedelta(days=7)
        two_weeks_ago = today - timedelta(days=14)
        now = datetime.now(UTC)
        
        # Get the user's active subscription using the same logic as increment_usage
        active_subscription = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date > datetime.now(UTC))
            .filter(SubscribedUser._is_active == True)
            .first()
        )
        
        # Set subscription status for template
        has_active_subscription = active_subscription is not None
        
        # Only proceed with detailed analytics if user has an active subscription
        if active_subscription:
            # Apply the same daily reset logic as increment_usage
            today_utc = datetime.now(UTC).date()
            last_reset_date = getattr(active_subscription, 'last_usage_reset', None)
            
            # Check if usage needs daily reset (same logic as increment_usage)
            if not last_reset_date or last_reset_date.date() < today_utc:
                # Reset counter for new day
                active_subscription.current_usage = 0
                active_subscription.last_usage_reset = datetime.now(UTC)
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Error resetting daily usage: {str(e)}")
            
            # Get token information
            total_daily_tokens = active_subscription.subscription.usage_per_day
            today_token_usage = active_subscription.current_usage
            available_tokens = max(0, total_daily_tokens - today_token_usage)
            token_usage_percentage = (today_token_usage / total_daily_tokens * 100) if total_daily_tokens > 0 else 0
            
            # Query recent analyses from search history (for URLs/queries)
            recent_analyses = SearchHistory.query.filter_by(u_id=user_id)\
                .order_by(SearchHistory.created_at.desc())\
                .limit(5)\
                .all()
            
            # Get yesterday's token usage from current_usage tracking or estimate from logs
            yesterday_start = datetime.combine(yesterday, datetime.min.time())
            yesterday_end = datetime.combine(yesterday, datetime.max.time())
            
            # Try to get yesterday's token usage from usage logs
            yesterday_logs = UsageLog.query.filter(
                UsageLog.user_id == user_id,
                UsageLog.timestamp >= yesterday_start,
                UsageLog.timestamp <= yesterday_end
            ).all()
            
            # Calculate yesterday's token usage by parsing details field
            yesterday_token_usage = 0
            for log in yesterday_logs:
                try:
                    # Extract tokens from details field (format: "... - Tokens used: X")
                    if log.details and "Tokens used:" in log.details:
                        import re
                        match = re.search(r'Tokens used: (\d+)', log.details)
                        if match:
                            yesterday_token_usage += int(match.group(1))
                        else:
                            # Fallback: assume 1 token if can't parse
                            yesterday_token_usage += 1
                    else:
                        # Fallback for old logs without token info
                        yesterday_token_usage += 1
                except:
                    yesterday_token_usage += 1
            
            # Calculate percentage change vs yesterday
            if yesterday_token_usage > 0:
                today_vs_yesterday = ((today_token_usage - yesterday_token_usage) / yesterday_token_usage) * 100
            else:
                today_vs_yesterday = 100 if today_token_usage > 0 else 0
            
            # Total token usage (estimate from all usage logs)
            all_logs = UsageLog.query.filter(UsageLog.user_id == user_id).all()
            total_token_usage = 0
            for log in all_logs:
                try:
                    if log.details and "Tokens used:" in log.details:
                        import re
                        match = re.search(r'Tokens used: (\d+)', log.details)
                        if match:
                            total_token_usage += int(match.group(1))
                        else:
                            total_token_usage += 1
                    else:
                        # Fallback for old logs
                        total_token_usage += 1
                except:
                    total_token_usage += 1
            
            # Calculate milestone progress based on token usage
            milestone_thresholds = [100, 500, 1000, 5000, 10000, 50000]
            next_milestone = next((m for m in milestone_thresholds if m > total_token_usage), milestone_thresholds[-1] * 2)
            previous_milestone = next((m for m in reversed(milestone_thresholds) if m < total_token_usage), 0)
            
            if next_milestone > previous_milestone:
                milestone_progress = int(((total_token_usage - previous_milestone) / (next_milestone - previous_milestone)) * 100)
            else:
                milestone_progress = 100  # At or beyond highest milestone
            
            # Get the user's top operation type
            top_operation_query = db.session.query(
                UsageLog.operation_type, 
                func.count(UsageLog.id).label('total')
            )\
            .filter(UsageLog.user_id == user_id)\
            .group_by(UsageLog.operation_type)\
            .order_by(func.count(UsageLog.id).desc())\
            .first()
            
            if top_operation_query:
                top_operation_type = top_operation_query[0]
            
            # Get tool distribution for visualization (weighted by token cost)
            tool_usage_query = db.session.query(
                UsageLog.operation_type,
                func.count(UsageLog.id).label('count')
            )\
            .filter(UsageLog.user_id == user_id)\
            .group_by(UsageLog.operation_type)\
            .order_by(func.count(UsageLog.id).desc())\
            .all()
            
            # Calculate tool distribution with token weighting
            tool_token_usage = {}
            
            # Define token costs for each operation
            OPERATION_TOKEN_COSTS = {
                'url_search': 1,
                'keyword_detail': 3,
                'h_detail': 1,
                'meta_detail': 2,
                'image_detail': 2,
                'loading': 5,  # site structure
                'site_structure': 2,
                # Add more as needed
            }
            
            for operation, count in tool_usage_query:
                # Get token cost for this operation (default to 1 if not defined)
                token_cost = OPERATION_TOKEN_COSTS.get(operation, 1)
                tool_token_usage[operation] = count * token_cost
            
            # Calculate percentages for tool distribution based on token usage
            total_tool_tokens = sum(tool_token_usage.values())
            
            if total_tool_tokens > 0:
                # Define CSS classes for different tools
                css_classes = ['primary', 'secondary', 'tertiary', 'quaternary', 'success', 'warning']
                
                tool_distribution = []
                for i, (tool, token_count) in enumerate(sorted(tool_token_usage.items(), key=lambda x: x[1], reverse=True)):
                    percentage = (token_count / total_tool_tokens) * 100
                    
                    # Clean up operation names for display
                    display_name = tool.replace('_', ' ').title()
                    if 'Detail' in display_name:
                        display_name = display_name.replace(' Detail', ' Analysis')
                    elif 'Ajax' in display_name:
                        display_name = display_name.replace(' Ajax', '')
                    
                    tool_distribution.append({
                        'name': display_name,
                        'percentage': round(percentage, 1),
                        'tokens': token_count,
                        'class': css_classes[i % len(css_classes)]
                    })
            
            # Calculate weekly trend based on token usage (this week vs. last week)
            this_week_start = week_ago
            last_week_start = two_weeks_ago
            last_week_end = week_ago
            
            # Get this week's logs
            this_week_logs = UsageLog.query.filter(
                UsageLog.user_id == user_id,
                UsageLog.timestamp >= this_week_start
            ).all()
            
            # Get last week's logs
            last_week_logs = UsageLog.query.filter(
                UsageLog.user_id == user_id,
                UsageLog.timestamp >= last_week_start,
                UsageLog.timestamp < last_week_end
            ).all()
            
            # Calculate token usage for each week
            this_week_tokens = 0
            for log in this_week_logs:
                try:
                    if log.details and "Tokens used:" in log.details:
                        import re
                        match = re.search(r'Tokens used: (\d+)', log.details)
                        if match:
                            this_week_tokens += int(match.group(1))
                        else:
                            this_week_tokens += 1
                    else:
                        operation = log.operation_type
                        this_week_tokens += OPERATION_TOKEN_COSTS.get(operation, 1)
                except:
                    this_week_tokens += 1
            
            last_week_tokens = 0
            for log in last_week_logs:
                try:
                    if log.details and "Tokens used:" in log.details:
                        import re
                        match = re.search(r'Tokens used: (\d+)', log.details)
                        if match:
                            last_week_tokens += int(match.group(1))
                        else:
                            last_week_tokens += 1
                    else:
                        operation = log.operation_type
                        last_week_tokens += OPERATION_TOKEN_COSTS.get(operation, 1)
                except:
                    last_week_tokens += 1
            
            # Calculate percentage change (avoid division by zero)
            if last_week_tokens > 0:
                weekly_trend = ((this_week_tokens - last_week_tokens) / last_week_tokens) * 100
            else:
                weekly_trend = 100 if this_week_tokens > 0 else 0

    # Prepare dashboard statistics
    dashboard_stats = {
        'today_tokens_used': today_token_usage,
        'available_tokens': available_tokens,
        'total_daily_tokens': total_daily_tokens,
        'token_usage_percentage': round(token_usage_percentage, 1),
        'total_lifetime_tokens': total_token_usage,
        'yesterday_comparison': round(today_vs_yesterday, 1),
        'weekly_trend': round(weekly_trend, 1),
        'milestone_progress': milestone_progress,
        'next_milestone': next_milestone if 'next_milestone' in locals() else 100
    }

    # Pass all data to template including subscription status and token info
    return render_template('index.html', 
                      user_name=user_name,
                      recent_analyses=recent_analyses,
                      websites_analyzed_today=today_token_usage,  # Now represents tokens used
                      total_analyses=total_token_usage,  # Now represents total tokens used
                      favorite_tool=top_operation_type,
                      weekly_trend=weekly_trend,
                      today_vs_yesterday=today_vs_yesterday,
                      tool_distribution=tool_distribution,
                      milestone_progress=milestone_progress,
                      now=now,
                      recent_activity=recent_activity,
                      links_data=None,
                      view_mode=view_mode,
                      has_active_subscription=has_active_subscription,
                      # New token-based stats
                      dashboard_stats=dashboard_stats,
                      available_tokens=available_tokens,
                      total_daily_tokens=total_daily_tokens,
                      token_usage_percentage=token_usage_percentage)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        company_email = request.form.get('companyEmail').lower().strip()
        password = request.form.get('password')

        user = User.query.filter(
            func.lower(User.company_email) == company_email
        ).first()

        if not user:
            flash("Invalid email or password.", "danger")
            return render_template('login.html', email_value=company_email)

        if not user.email_confirmed:
            flash("Please verify your email before logging in. Check your inbox or request a new verification link.", "warning")
            return redirect(url_for('resend_verification'))

        if user.check_password(password):
            login_user(user)
            user.update_last_login()
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password.", "danger")
            return render_template('login.html', email_value=company_email)

    return render_template('login.html', email_value='')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name', '').strip()
        company_email = request.form.get('companyEmail', '').lower().strip()
        password = request.form.get('password', '')
        retype_password = request.form.get('retypePassword', '')
        
        # Enhanced input validation
        errors = []
        
        # Name validation
        if not name:
            errors.append("Name is required.")
        elif len(name) < 2:
            errors.append("Name should be at least 2 characters long.")
        elif len(name) > 100:
            errors.append("Name should not exceed 100 characters.")
        
        # Email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not company_email:
            errors.append("Email is required.")
        elif not re.match(email_pattern, company_email):
            errors.append("Please enter a valid email address.")
        elif len(company_email) > 255:
            errors.append("Email address is too long.")
        
        # Password validation
        if not password:
            errors.append("Password is required.")
        elif len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        elif len(password) > 128:
            errors.append("Password should not exceed 128 characters.")
        else:
            # Check password complexity
            password_errors = []
            if not re.search(r'[A-Z]', password):
                password_errors.append("one uppercase letter")
            if not re.search(r'[a-z]', password):
                password_errors.append("one lowercase letter")
            if not re.search(r'[0-9]', password):
                password_errors.append("one number")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                password_errors.append("one special character")
            
            if password_errors:
                errors.append(f"Password must contain at least {', '.join(password_errors)}.")
        
        # Password confirmation validation
        if password and retype_password and password != retype_password:
            errors.append("Passwords do not match.")
        elif not retype_password:
            errors.append("Please confirm your password.")
        
        # Check if email already exists (only if email is valid)
        if company_email and re.match(email_pattern, company_email):
            try:
                existing_user = User.query.filter(
                    func.lower(User.company_email) == company_email
                ).first()
                
                if existing_user:
                    if existing_user.email_confirmed:
                        errors.append("This email is already registered and verified.")
                    else:
                        errors.append("This email is already registered but not verified. Please check your email or contact support.")
            except Exception as e:
                logging.error(f"Database error during email check: {str(e)}")
                errors.append("A system error occurred. Please try again.")
        
        # If there are any errors, flash them and return to form
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template('signup.html', name=name, company_email=company_email)
        
        # Create new user
        try:
            new_user = User(name=name, company_email=company_email, email_confirmed=False)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            # Send verification email
            try:
                send_verification_email(new_user)
                flash("Signup successful! Please check your email to verify your account.", "success")
                logging.info(f"New user registered: {company_email}")
            except Exception as e:
                logging.error(f"Error sending verification email to {company_email}: {str(e)}")
                flash("Signup successful but there was an issue sending the verification email. Please contact support.", "warning")
            
            # Redirect to verify account page with email parameter
            return redirect(url_for('verify_account', email=company_email))
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Database error during user creation: {str(e)}")
            flash("A system error occurred during registration. Please try again.", "danger")
            return render_template('signup.html', name=name, company_email=company_email)
    
    # GET request - show the signup form
    return render_template('signup.html')

@app.route('/check_email', methods=['POST'])
def check_email():
    """Check if email is already registered with CSRF protection"""
    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
            email = data.get('email', '').lower().strip()
            csrf_token = data.get('csrf_token', '')
        else:
            email = request.form.get('email', '').lower().strip()
            csrf_token = request.form.get('csrf_token', '')
        
        # Validate CSRF token if CSRF protection is enabled
        if app.config.get('WTF_CSRF_ENABLED', False):
            try:
                from flask_wtf.csrf import validate_csrf
                # Try to validate CSRF token from different sources
                token_to_validate = (
                    csrf_token or 
                    request.headers.get('X-CSRFToken') or 
                    request.headers.get('X-CSRF-Token')
                )
                if token_to_validate:
                    validate_csrf(token_to_validate)
            except Exception as csrf_error:
                app.logger.warning(f"CSRF validation failed for email check: {str(csrf_error)}")
                return jsonify({
                    'available': False, 
                    'message': 'Security token validation failed. Please refresh the page and try again.'
                }), 400
        
        # Basic input validation
        if not email:
            return jsonify({'available': True, 'message': ''})
        
        # Validate email format first
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({
                'available': False, 
                'message': 'Please enter a valid email address.'
            })
        
        # Check if email already exists (case-insensitive)
        existing_user = User.query.filter(
            func.lower(User.company_email) == email
        ).first()
        
        if existing_user:
            return jsonify({
                'available': False, 
                'message': 'This email is already registered. Please use a different email or <a href="/login">login here</a>.'
            })
        else:
            return jsonify({
                'available': True, 
                'message': 'Email is available.'
            })
            
    except Exception as e:
        app.logger.error(f"Error checking email availability: {str(e)}")
        return jsonify({
            'available': False, 
            'message': 'Unable to verify email availability. Please try again.'
        }), 500
    
# Replace your existing verify_account route in app.py with this corrected version

@app.route("/verify_account")
def verify_account():
    email = request.args.get('email')
    return render_template('verify_account.html', email=email)

# Add this route to your app.py file (around line 1500, after your other auth routes)

@app.route('/verify_email/<token>')
def verify_email(token):
    """Verify email address using token"""
    try:
        user = User.verify_email_token(token)
        
        if user is None:
            flash('The verification link is invalid or has expired. Please request a new verification email.', 'danger')
            return redirect(url_for('resend_verification'))
        
        if user.email_confirmed:
            flash('Your email has already been verified. You can log in.', 'info')
            return redirect(url_for('login'))
        
        # Mark email as confirmed
        user.email_confirmed = True
        user.email_confirm_token = None  # Clear the token
        user.email_token_created_at = None  # Clear the token timestamp
        db.session.commit()
        
        flash('Your email has been verified successfully! You can now log in.', 'success')
        logging.info(f"Email verified successfully for user: {user.company_email}")
        return redirect(url_for('login'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error verifying email with token {token}: {str(e)}")
        flash('An error occurred while verifying your email. Please try again or contact support.', 'danger')
        return redirect(url_for('signup'))
# Replace your existing resend_verification route in app.py with this corrected version
# Make sure it's properly indented and not inside another function

@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('companyEmail', '').lower().strip()
        
        if not email:
            flash('Please enter your email address.', 'warning')
            return render_template('resend_verification.html')
        
        user = User.query.filter(
            func.lower(User.company_email) == email
        ).first()
        
        if user and not user.email_confirmed:
            try:
                send_verification_email(user)
                flash('A new verification email has been sent to your email address.', 'success')
                # Redirect back to verify account page with email
                return redirect(url_for('verify_account', email=email))
            except Exception as e:
                logging.error(f"Error resending verification email: {str(e)}")
                flash('There was an issue sending the verification email. Please try again later.', 'danger')
        elif user and user.email_confirmed:
            flash('This email is already verified. You can log in.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found. Please sign up first.', 'warning')
            return redirect(url_for('signup'))
    
    # GET request - show the resend verification form
    return render_template('resend_verification.html')

# Replace your existing reset_request route in app.py with this fixed version:

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('companyEmail', '').lower().strip()
        
        # Validate email input
        if not email:
            flash('Please enter your email address.', 'warning')
            return render_template('reset_request.html')
        
        user = User.query.filter(
            func.lower(User.company_email) == email
        ).first()
        
        if user:
            try:
                send_reset_email(user)
                flash('An email has been sent with instructions to reset your password.', 'info')
                return redirect(url_for('login'))
            except Exception as e:
                logging.error(f"Error sending reset email: {str(e)}")
                flash('There was an issue sending the reset email. Please try again later.', 'danger')
                return render_template('reset_request.html')
        else:
            # IMPORTANT: Always return a response - this was missing!
            flash('Email not found. Please register first.', 'warning')
            return render_template('reset_request.html')
    
    # GET request - show the reset request form
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        # Try to verify the token
        user = User.verify_reset_token(token)
        if not user:
            flash('Invalid or expired token. Please request a new password reset link.', 'danger')
            return redirect(url_for('reset_request'))

        if request.method == 'POST':
            # Handle password reset logic here
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validate passwords
            if not password or not confirm_password:
                flash('Both password fields are required', 'danger')
                return render_template('reset_token.html', token=token)
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return render_template('reset_token.html', token=token)
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return render_template('reset_token.html', token=token)

            # Update password
            user.set_password(password)
            user.password_reset_at = datetime.now(UTC)
            db.session.commit()

            flash('Your password has been updated! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))

    except Exception as e:
        # Log any errors
        logging.error(f"Error during password reset: {str(e)}")
        flash('An error occurred during the password reset process. Please try again.', 'danger')
        return redirect(url_for('reset_request'))

    # If method is GET, render the reset password page
    return render_template('reset_token.html', token=token)

@app.route('/logout')
def logout():
    logout_user()  # Flask-Login function
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))
# ---------------------------------------
# Profile Management Routes
# ---------------------------------------
from flask import render_template, request, session, flash, render_template_string
from flask_login import login_required
from datetime import datetime, timedelta, timezone
import pytz

@app.route('/search_history', methods=['GET'])
@login_required
def search_history():
    user_id = session.get('user_id')
    
    # Fetch the user name
    user = db.session.get(User, user_id)
    user_name = user.name if user else "Guest"

    # Fetch optional date filters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = SearchHistory.query.filter_by(u_id=user_id)

    # Date filtering logic
    try:
        if start_date:
            start_obj = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(SearchHistory.created_at >= start_obj)

        if end_date:
            end_obj = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(SearchHistory.created_at < end_obj)
    except ValueError:
        flash("Invalid date format. Use YYYY-MM-DD.", "danger")

    history = query.order_by(SearchHistory.created_at.desc()).all()

    # Get most used tool per user (only once)
    user_most_used_tools = {}
    if history:
        tool_usage = (
            db.session.query(SearchHistory.usage_tool, db.func.sum(SearchHistory.search_count))
            .filter(SearchHistory.u_id == user_id)
            .group_by(SearchHistory.usage_tool)
            .all()
        )
        if tool_usage:
            most_used_tool = max(tool_usage, key=lambda x: x[1])[0]
            user_most_used_tools[user_id] = most_used_tool
        else:
            user_most_used_tools[user_id] = "No tools used yet"

    # Format each history item
    for entry in history:
        if entry.created_at:
            if entry.created_at.tzinfo is None:
                entry.formatted_date = pytz.UTC.localize(entry.created_at).strftime('%d-%m-%Y %I:%M:%S %p UTC')
            else:
                entry.formatted_date = entry.created_at.astimezone(pytz.UTC).strftime('%d-%m-%Y %I:%M:%S %p UTC')
        else:
            entry.formatted_date = 'N/A'

    return render_template(
        'search_history.html',
        history=history,
        user_name=user_name,
        user_most_used_tools=user_most_used_tools,
        start_date=start_date,
        end_date=end_date
    )


# ---------------------------------------
# Profile Management Routes
# ---------------------------------------

@app.route('/profile')
@login_required
def profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    # Get current time (timezone-naive to match database datetimes)
    now = datetime.now()
    
    # Use SAME query logic as subscriptions page
    active_subscription = None
    subscriptions = (
        db.session.query(SubscribedUser, Subscription)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > now)
        .filter(SubscribedUser._is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .order_by(SubscribedUser.start_date.desc())  # Get newest subscription
        .all()
    )
    
    # Get the most recent active subscription (same logic as subscriptions page)
    if len(subscriptions) > 1:
        # Keep only the most recent active subscription
        active_subscription = subscriptions[0]  # Tuple of (SubscribedUser, Subscription)
        
        # Deactivate all other active subscriptions
        for sub, plan in subscriptions[1:]:
            sub.is_active = False
        db.session.commit()
    elif len(subscriptions) == 1:
        active_subscription = subscriptions[0]  # Tuple of (SubscribedUser, Subscription)
    
    # Get recent payments
    payments = (
        Payment.query
        .filter_by(user_id=user_id)
        .order_by(Payment.created_at.desc())
        .limit(10)
        .all()
    )
    
    # FIXED: Get actual recent activity data
    recent_activity = {
        'last_login': user.get_last_login_display(),
        'profile_updated': user.get_profile_updated_display(),
        'password_changed': user.get_password_changed_display()
    }
    
    return render_template('profile.html', 
                          user=user, 
                          active_subscription=active_subscription,  # Pass the tuple like in subscriptions.html
                          payments=payments,
                          recent_activity=recent_activity,  # FIXED: Pass the correct activity data
                          now=now)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    update_type = request.form.get('update_type')
    
    if update_type == 'account':
        # Update account information
        new_name = request.form.get('name', '').strip()
        
        if new_name and len(new_name) >= 2:
            user.name = new_name
            # FIXED: Update the profile timestamp when profile is updated
            user.update_profile_timestamp()
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        else:
            flash('Name must be at least 2 characters long.', 'danger')
    
    elif update_type == 'security':
        # Update password
        current_password = request.form.get('currentPassword')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        
        # Verify current password
        if not current_password or not user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
        elif not new_password or len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        else:
            # Password strength validation
            import re
            if not (re.search(r'[A-Z]', new_password) and 
                   re.search(r'[a-z]', new_password) and 
                   re.search(r'[0-9]', new_password) and 
                   re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password)):
                flash('Password must contain uppercase, lowercase, number and special character.', 'danger')
            else:
                # FIXED: Use the User model's set_password method which properly updates the timestamp
                user.set_password(new_password)
                db.session.commit()
                flash('Password updated successfully!', 'success')
    
    return redirect(url_for('profile'))

# Additional helper function to get current usage (for dashboard consistency)
def get_current_usage(user_id):
    """
    Get current usage count with daily reset logic (read-only)
    Returns current usage count and subscription info
    """
    sub = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .filter(SubscribedUser._is_active == True)
        .first()
    )
    
    if sub:
        # Check if we need to reset the usage counter (new day)
        today = datetime.now(UTC).date()
        last_reset_date = getattr(sub, 'last_usage_reset', None)
        
        if not last_reset_date or last_reset_date.date() < today:
            # Reset counter for new day
            sub.current_usage = 0
            sub.last_usage_reset = datetime.now(UTC)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error resetting daily usage: {str(e)}")
        
        return {
            'current_usage': sub.current_usage,
            'daily_limit': sub.subscription.usage_per_day,
            'subscription': sub
        }
    
    return None


# Generate a downloadable payment receipt
@app.route('/receipt/<payment_id>')
@login_required
def download_receipt(payment_id):
    user_id = session.get('user_id')
    
    # Get payment details
    payment = Payment.query.filter_by(id=payment_id, user_id=user_id).first_or_404()
    
    # TODO: Generate and return PDF receipt
    # This would typically use a PDF generation library like ReportLab or WeasyPrint
    
    flash('Receipt download feature coming soon!', 'info')
    return redirect(url_for('profile') + '#activity')

# --------------------------------
# app primary functions routes
# -------------------------------- 

@app.template_filter('urlparse')
def urlparse_filter(url):
    return urlparse(url)
# Add this to your app.py to replace the existing url_search route

@app.route('/url_search', methods=['GET', 'POST'])
@login_required
@subscription_check_only
# @subscription_required_with_tokens(0)
def url_search():
    links_data = None
    url_input = request.args.get('url', '')
    robots_info = None
    
    # Check for refresh or clear request
    if request.args.get('refresh') == 'true':
        clear_search_results('url_search')
        return redirect(url_for('url_search'))
    
    if request.method == 'POST' and not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        url_input = request.form.get('url')
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            try:
                home_links, other_links, robots_info = analyze_links(
                    url=url_input,
                    respect_robots=respect_robots
                )
                
                # Extract domains for external links
                other_links_with_domains = []
                for link in other_links:
                    try:
                        parsed = urlparse(link)
                        domain = parsed.netloc
                        other_links_with_domains.append({
                            'url': link,
                            'domain': domain
                        })
                    except:
                        other_links_with_domains.append({
                            'url': link,
                            'domain': 'unknown'
                        })
                        
                links_data = {
                    'home': home_links, 
                    'other': other_links,
                    'other_with_domains': other_links_with_domains
                }
                
                # Store in cache instead of session
                store_search_results('url_search', url_input, home_links, other_links, robots_info)
                
                # Capture the search history
                u_id = session.get('user_id')
                usage_tool = "URL Search"
                add_search_history(u_id, usage_tool, url_input)
                    
            except Exception as e:
                app.logger.error(f"Error analyzing URL: {str(e)}")
                flash(f"Error analyzing URL: {str(e)}", "danger")
                return redirect(url_for('url_search'))
    
    # Get data from cache if available
    if not links_data and url_input:
        url_input, links_data, robots_info = get_search_results('url_search')
    
    return render_template(
        'url_search.html', 
        url_input=url_input, 
        links_data=links_data,
        robots_info=robots_info
    )

# ===== 2. URL SEARCH AJAX ROUTE =====
@app.route('/url_search_ajax', methods=['POST'])
@login_required
@subscription_required_with_tokens(1)
@csrf.exempt
def url_search_ajax():
    links_data = None
    url_input = request.form.get('url', '')
    respect_robots = request.form.get('respect_robots') == 'on'
    robots_info = None
    
    if url_input:
        try:
            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"error": "Please log in to continue."}), 401
            
            # Clear previous cache before new search
            clear_search_results('url_search')
                
            home_links, other_links, robots_info = analyze_links(
                url=url_input,
                respect_robots=respect_robots
            )
            
            # Extract domains for external links
            other_links_with_domains = []
            for link in other_links:
                try:
                    parsed = urlparse(link)
                    domain = parsed.netloc
                    other_links_with_domains.append({
                        'url': link,
                        'domain': domain
                    })
                except:
                    other_links_with_domains.append({
                        'url': link,
                        'domain': 'unknown'
                    })
                    
            links_data = {
                'home': home_links, 
                'other': other_links,
                'other_with_domains': other_links_with_domains
            }
            
            # Store in cache
            store_search_results('url_search', url_input, home_links, other_links, robots_info)
            
        except Exception as e:
            app.logger.error(f"Error analyzing URL: {str(e)}")
            return jsonify({"error": f"Error analyzing URL: {str(e)}"}), 500
    
    return render_template(
        'url_search_results.html',
        url_input=url_input,
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/record_search', methods=['POST'])
@login_required
@csrf.exempt
def record_search():
    data = request.get_json()
    if not data or 'url' not in data or 'tool' not in data:
        return jsonify({"success": False, "message": "Missing required parameters"}), 400
    
    try:
        u_id = session.get('user_id')
        add_search_history(u_id, data['tool'], data['url'])
        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"Error recording search: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/download_url')
@login_required
def download_url():
    url_input = request.args.get('url')
    respect_robots = request.args.get('respect_robots', 'true') == 'true'
    
    if not url_input:
        flash("No URL provided for download.")
        return redirect(url_for('url_search'))

    try:
        # FIXED: Use correct function call with named parameters
        home_links, other_links, robots_info = analyze_links(
            url=url_input, 
            respect_robots=respect_robots
        )

        # Prepare a list of dictionaries for CSV export
        data = []
        
        # Add home links
        for link in home_links:
            data.append({
                "Link": link,
                "Type": "Home",
                "Allowed": "Yes"
            })
        
        # Add external links
        for link in other_links:
            data.append({
                "Link": link,
                "Type": "External",
                "Allowed": "Yes"
            })
        
        # If robots.txt was analyzed, include disallowed links
        if robots_info and robots_info.get('parser_id'):
            # Get the parser from the global dictionary
            parser_id = robots_info.get('parser_id')
            parser = None
            
            if hasattr(analyze_robots_txt, 'parsers'):
                parser = analyze_robots_txt.parsers.get(parser_id)
            
            if parser:
                # Check if there are any disallowed links we filtered out
                base_domain = urlparse(url_input).netloc
                if base_domain.startswith("www."):
                    base_domain = base_domain[4:]
                    
                disallow_rules = robots_info.get('disallow_rules', [])
                
                # Add a section for disallowed links if we have rules
                if disallow_rules:
                    data.append({
                        "Link": "--- DISALLOWED LINKS (NOT CRAWLED) ---",
                        "Type": "",
                        "Allowed": ""
                    })
                    
                    # Add details about robots.txt
                    data.append({
                        "Link": f"robots.txt for {base_domain}",
                        "Type": "Info",
                        "Allowed": "N/A"
                    })
                    
                    for rule in disallow_rules:
                        data.append({
                            "Link": f"{urlparse(url_input).scheme}://{base_domain}{rule}",
                            "Type": "Disallowed",
                            "Allowed": "No"
                        })

        # Save CSV file in the download directory
        file_path = os.path.join(download_dir, 'links.csv')
        with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=["Link", "Type", "Allowed"])
            writer.writeheader()
            writer.writerows(data)

        # Add robots.txt information to the filename
        filename = 'links_with_robots.csv' if respect_robots else 'links.csv'

        return send_file(file_path, mimetype='text/csv', as_attachment=True, download_name=filename)
        
    except Exception as e:
        app.logger.error(f"Error in download_url: {str(e)}")
        flash(f"Error generating download: {str(e)}", "danger")
        return redirect(url_for('url_search'))


# Helper functions - replace these with your actual subscription logic
def check_user_subscription(user_id):
    """
    Replace this with your actual subscription checking logic
    Should return True if user has valid subscription, False otherwise
    """
    # Your subscription checking logic here
    # Example: return db.session.query(Subscription).filter_by(user_id=user_id, active=True).first() is not None
    return True  # Placeholder - replace with actual logic

def deduct_user_token(user_id):
    """
    Replace this with your actual token deduction logic
    Should deduct one token and return True if successful, False if insufficient tokens
    """
    # Your token deduction logic here
    # Example:
    # user = db.session.query(User).filter_by(id=user_id).first()
    # if user and user.tokens > 0:
    #     user.tokens -= 1
    #     db.session.commit()
    #     return True
    # return False
    return True  # Placeholder - replace with actual logic

@app.route('/keyword_search', methods=['GET', 'POST'])
@login_required
@subscription_check_only
def keyword_search():
    url_input = ""
    links_data = None
    robots_info = None
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            try:
                home_links, other_links, robots_info = analyze_links(
                    url=url_input,
                    respect_robots=respect_robots
                )
                
                # Store the search history
                u_id = session.get('user_id')
                usage_tool = "Keyword Search"
                add_search_history(u_id, usage_tool, url_input)
                
                # Store in cache instead of session
                store_search_results('keyword_search', url_input, home_links, other_links, robots_info)

                # Redirect to prevent form resubmission
                return redirect(url_for('keyword_search', url=url_input))
                
            except Exception as e:
                app.logger.error(f"Error in keyword_search: {str(e)}")
                flash(f"Error analyzing URL: {str(e)}", "danger")
                return redirect(url_for('keyword_search'))

    # Clear cache if there's no URL parameter (fresh page load)
    if 'url' not in request.args:
        clear_search_results('keyword_search')
        url_input = ""
        links_data = None
        robots_info = None
    else:
        # Retrieve from cache
        url_input = request.args.get('url', "")
        if url_input:
            stored_url, links_data, robots_info = get_search_results('keyword_search')
            # Use the URL from the parameter if cache doesn't match
            if stored_url != url_input:
                links_data = None
                robots_info = None

    return render_template(
        'keyword_search.html', 
        url_input=url_input, 
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/keyword_detail', methods=['GET', 'POST'])
@login_required
@subscription_required_with_tokens(3)
def keyword_detail():
    link = request.args.get('link')
    if not link:
        flash("No link provided for keyword analysis.")
        return redirect(url_for('keyword_search'))
    
    # Get home links from cache
    stored_url, links_data, robots_info = get_search_results('keyword_search')
    home_links = links_data.get('home', []) if links_data else []
    
    extracted_text = extract_text(link)
    keyword_results = None
    corrected_results = None
    keywords_input = ""
    colors = ["blue", "green", "brown", "purple", "orange", "teal", "maroon", "navy", "olive", "magenta"]
    
    if request.method == 'POST':
        keywords_input = request.form.get('keywords', '')
        keywords_list = [k.strip() for k in keywords_input.split(',') if k.strip()]
        if len(keywords_list) > 10:
            keywords_list = keywords_list[:10]
        keyword_results = process_keywords(extracted_text, keywords_list)
        corrected_results = correct_text(extracted_text)
    
    keywords_colors = {}
    if keyword_results:
        for i, (kw, data) in enumerate(keyword_results["keywords"].items()):
            keywords_colors[kw] = colors[i] if i < len(colors) else 'black'
    
    return render_template('keyword_detail.html',
                           link=link,
                           extracted_text=extracted_text,
                           keyword_results=keyword_results,
                           corrected_results=corrected_results,
                           keywords_input=keywords_input,
                           colors=colors,
                           home_links=home_links,
                           keywords_colors=keywords_colors,
                           current_time=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
            )

@app.route('/download_keyword_txt')
@login_required
def download_keyword_txt():
    link = request.args.get('link')
    keywords_input = request.args.get('keywords_input', '')
    
    if not link:
        flash("No link provided for download.")
        return redirect(url_for('keyword_search'))
    
    extracted_text = extract_text(link)
    cleaned_text = " ".join(extracted_text.split())
    
    output_text = cleaned_text
    analysis_text = "No keywords provided for analysis."
    
    if keywords_input:
        keywords_list = [k.strip() for k in keywords_input.split(',') if k.strip()]
        if keywords_list:
            keyword_results = process_keywords(extracted_text, keywords_list)
            analysis_lines = []
            for keyword, data in keyword_results["keywords"].items():
                line = f"Keyword: {keyword}, Count: {data['count']}, Density: {round(data['density'], 2)}%"
                analysis_lines.append(line)
            analysis_text = "\n".join(analysis_lines)
    
    output = f"Extracted Text:\n{output_text}\n\nKeyword Analysis:\n{analysis_text}"
    file_path = os.path.join(download_dir, 'keyword_analysis.txt')
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(output)
    
    return send_file(file_path, mimetype='text/plain', as_attachment=True, download_name='keyword_analysis.txt')


@app.route('/image_search', methods=['GET', 'POST'])
@login_required
@subscription_check_only
def image_search():
    links_data = None
    url_input = ""
    robots_info = None
    
    # Check if this is a refresh request
    is_refresh = request.args.get('refresh') == 'true'
    
    # Check if we're coming from another page (not a form submission)
    coming_from_another_page = request.method == 'GET' and not is_refresh and request.referrer and 'image_search' not in request.referrer
    
    # Clear cache data on refresh or when coming from another page
    if is_refresh or coming_from_another_page:
        clear_search_results('image_search')
        if is_refresh:
            return redirect(url_for('image_search'))
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        # Get URL from the mobile input if desktop input is empty
        if not url_input:
            url_input = request.form.get('mobile-url')
            
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            try:
                home_links, other_links, robots_info = analyze_links(
                    url=url_input,
                    respect_robots=respect_robots
                )
                
                # Store the search history
                u_id = session.get('user_id')
                usage_tool = "Image Search"
                add_search_history(u_id, usage_tool, url_input)
                
                # Store in cache instead of session
                store_search_results('image_search', url_input, home_links, other_links, robots_info)
                
                # Redirect after POST to prevent form resubmission
                return redirect(url_for('image_search', processed='true'))
                
            except Exception as e:
                app.logger.error(f"Error in image_search: {str(e)}")
                flash(f"Error analyzing URL: {str(e)}", "error")
                return redirect(url_for('image_search'))
    else:
        # Retrieve from cache if not coming from another page
        if not coming_from_another_page:
            url_input, links_data, robots_info = get_search_results('image_search')
    
    return render_template(
        'image_search.html',
        url_input=url_input,
        links_data=links_data,
        robots_info=robots_info
    )


@app.route('/image_detail', methods=['GET'])
@login_required
@subscription_required_with_tokens(2)
def image_detail():
    link = request.args.get('link')
    if not link:
        flash("No link provided for image analysis.")
        return redirect(url_for('image_search'))
    
    cache_key = f"images_{link}"
    images = cache.get(cache_key)
    
    if images is None:
        try:
            images = extract_images(link)
            # Ensure images is always a list
            if images is None:
                images = []
            cache.set(cache_key, images)
        except Exception as e:
            flash(f"Error extracting images: {str(e)}", "error")
            return redirect(url_for('image_search'))
    
    return render_template('image_detail.html', link=link, images=images)

@app.route('/download_image_csv')
@login_required
def download_image_csv():
    link = request.args.get('link')
    if not link:
        flash("No link provided for download.")
        return redirect(url_for('image_search'))

    cache_key = f"images_{link}"
    images = cache.get(cache_key)
    if images is None:
        try:
            images = extract_images(link)
            cache.set(cache_key, images)
        except Exception as e:
            flash(f"Error extracting images for download: {str(e)}", "error")
            return redirect(url_for('image_search'))

    # Prepare a path for saving our CSV
    file_path = os.path.join(download_dir, 'images.csv')

    # Figure out which columns (field names) we have:
    # if `images` is empty, fall back to known columns
    if images:
        fieldnames = images[0].keys()  # e.g. ["image_number", "url", ...]
    else:
        fieldnames = ["image_number", "url", "alt_text", "title", "file_extension", "file_size", "resolution"]

    try:
        # Write CSV via built-in DictWriter
        with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(images)

        return send_file(file_path, mimetype='text/csv', as_attachment=True, download_name='images.csv')
    except Exception as e:
        flash(f"Error generating CSV file: {str(e)}", "error")
        return redirect(url_for('image_search'))

@app.route('/h_search', methods=['GET', 'POST'])
@login_required
@subscription_check_only
def h_search():
    url_input = ""
    links_data = None
    robots_info = None
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            try:
                home_links, other_links, robots_info = analyze_links(
                    url=url_input,
                    respect_robots=respect_robots
                )
                
                # Store the search history
                u_id = session.get('user_id')
                usage_tool = "Heading Search"
                add_search_history(u_id, usage_tool, url_input)
                
                # Store in cache instead of session
                store_search_results('h_search', url_input, home_links, other_links, robots_info)

                # Redirect to prevent form resubmission
                return redirect(url_for('h_search', url=url_input))
                
            except Exception as e:
                app.logger.error(f"Error in h_search: {str(e)}")
                flash(f"Error analyzing URL: {str(e)}", "danger")
                return redirect(url_for('h_search'))

    # Clear cache if there's no URL parameter (fresh page load)
    if 'url' not in request.args:
        clear_search_results('h_search')
        url_input = ""
        links_data = None
        robots_info = None
    else:
        # Retrieve from cache
        url_input = request.args.get('url', "")
        if url_input:
            stored_url, links_data, robots_info = get_search_results('h_search')

    return render_template(
        'h_search.html', 
        url_input=url_input, 
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/h_detail', methods=['GET'])
@login_required
@subscription_required_with_tokens(1)
def h_detail():
    url_input = request.args.get('url')
    if not url_input:
        flash("No URL provided for H Tags analysis.")
        return redirect(url_for('h_search'))

    # Extract headings in DOM order
    headings_in_order = extract_headings_in_order(url_input)

    # Count how many of each tag
    tag_counts = Counter(h["tag"] for h in headings_in_order)

    # Get home links from cache
    stored_url, links_data, robots_info = get_search_results('h_search')
    home_links = links_data.get('home', []) if links_data else []

    # Check if all H1s are under 60 chars
    h1_headings = [h for h in headings_in_order if h['tag'] == 'h1']
    all_h1_under_60 = all(len(h['text']) < 60 for h in h1_headings)

    return render_template(
        'h_detail.html',
        url_input=url_input,
        headings_in_order=headings_in_order,
        tag_counts=tag_counts,
        home_links=home_links,
        all_h1_under_60=all_h1_under_60
    )

@app.route('/download_h_csv')
@login_required
def download_h_csv():
    url_input = request.args.get('url')
    if not url_input:
        flash("No URL provided for download.")
        return redirect(url_for('h_search'))
    
    # Use the function that returns headings in order
    headings_in_order = extract_headings_in_order(url_input)

    # Convert data into a list of dictionaries for CSV
    data = []
    for h in headings_in_order:
        data.append({
            'Tag': h['tag'].upper(),
            'Heading': h['text'],
            'HeadingLength': len(h['text']),
            'Level': h['level']
        })

    # Ensure the download directory exists
    os.makedirs(download_dir, exist_ok=True)

    # Write CSV via built-in csv library
    file_path = os.path.join(download_dir, 'headings.csv')
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['Tag', 'Heading', 'HeadingLength', 'Level']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    return send_file(
        file_path,
        mimetype='text/csv',
        as_attachment=True,
        download_name='headings.csv'
    )

@app.route('/meta_search', methods=['GET', 'POST'])
@login_required
@subscription_check_only
def meta_search():
    links_data = None
    url_input = ""
    robots_info = None
    
    # Check if this is a refresh request
    is_refresh = request.args.get('refresh') == 'true'
    
    # Check if we're coming from another page
    coming_from_another_page = request.method == 'GET' and not is_refresh and request.referrer and 'meta_search' not in request.referrer
    
    # Clear cache data on refresh or when coming from another page
    if is_refresh or coming_from_another_page:
        clear_search_results('meta_search')
        if is_refresh:
            return redirect(url_for('meta_search'))
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        # Get URL from the mobile input if desktop input is empty
        if not url_input:
            url_input = request.form.get('mobile-url')
            
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            try:
                home_links, other_links, robots_info = analyze_links(
                    url=url_input,
                    respect_robots=respect_robots
                )
                
                # Store the search history
                u_id = session.get('user_id')
                usage_tool = "Meta Search"
                add_search_history(u_id, usage_tool, url_input)
                
                # Store in cache instead of session
                store_search_results('meta_search', url_input, home_links, other_links, robots_info)
                
                # Implement POST-Redirect-GET pattern
                return redirect(url_for('meta_search', search_completed='true'))
                
            except Exception as e:
                app.logger.error(f"Error in meta_search: {str(e)}")
                flash("An error occurred while analyzing the URL. Please try again.", "danger")
                return redirect(url_for('meta_search'))
    else:
        # Handle GET request (including redirects from POST)
        search_completed = request.args.get('search_completed') == 'true'
        
        # Retrieve from cache if not coming from another page
        if not coming_from_another_page:
            url_input, links_data, robots_info = get_search_results('meta_search')
    
    return render_template(
        'meta_search.html',
        url_input=url_input,
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/meta_detail')
@login_required
@subscription_required_with_tokens(2)
def meta_detail():
    link = request.args.get('link')
    if not link:
        flash("No link provided for meta analysis.", "warning")
        return redirect(url_for('meta_search'))

    try:
        # Get links data from cache if available
        stored_url, links_data, robots_info = get_search_results('meta_search')
        
        # If no cached data, analyze the link
        if not links_data:
            home_links, other_links, robots_info = analyze_links(url=link)
            links_data = {
                'home': home_links,
                'other': other_links
            }

        # Extract meta information
        meta_info = extract_seo_data(link)
        
        if meta_info.get('error'):
            flash(meta_info['error'], 'danger')
            return redirect(url_for('meta_search'))
        
        return render_template(
            'meta_detail.html', 
            link=link, 
            meta_info=meta_info, 
            links_data=links_data,
            robots_info=robots_info
        )
    
    except Exception as e:
        app.logger.error(f"Error in meta_detail: {str(e)}")
        app.logger.error(traceback.format_exc())
        
        flash("An error occurred while analyzing the URL.", "danger")
        return redirect(url_for('meta_search'))

@app.route('/download_meta_csv')
@login_required
def download_meta_csv():
    link = request.args.get('link')
    if not link:
        flash("No link provided for download.")
        return redirect(url_for('meta_search'))
    
    meta_info = extract_seo_data(link)
    if meta_info.get('error'):
        flash(meta_info['error'])
        return redirect(url_for('meta_search'))

    # Convert the SEO data into a CSV-friendly format
    data = []
    # Title row
    data.append({
        'Type': 'title',
        'Attribute': 'title',
        'Content': meta_info['title']
    })
    # Meta tags
    for m in meta_info['meta_tags']:
        data.append({
            'Type': 'meta',
            'Attribute': m['attribute'],
            'Content': m['content']
        })
    # Schema (JSON-LD)
    for s in meta_info['schema']:
        data.append({
            'Type': 'schema',
            'Attribute': 'JSON-LD',
            'Content': json.dumps(s)  # convert the schema object to a JSON string
        })

    # Ensure the download directory exists
    os.makedirs(download_dir, exist_ok=True)

    # Write CSV file using built-in csv
    file_path = os.path.join(download_dir, 'meta_data.csv')
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['Type', 'Attribute', 'Content']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    return send_file(
        file_path,
        mimetype='text/csv',
        as_attachment=True,
        download_name='meta_data.csv'
    )
# ----------------------
# Site Structure Routes
# ----------------------
@app.route("/site_structure", methods=["GET", "POST"])
@subscription_check_only
@login_required
def site_structure():
    # Handle GET request with URL parameter (from recent analyses)
    if request.method == "GET":
        url_param = request.args.get('url')
        if url_param:
            # Auto-submit the form when URL is provided via GET parameter
            # This allows direct access from recent analyses
            return render_template("site_structure.html", auto_submit_url=url_param)
        else:
            # Regular GET request - show empty form
            return render_template("site_structure.html")
    
    # Handle POST request (form submission)
    if request.method == "POST":
        start_url = request.form["url"]
        
        if not start_url:
            return render_template("site_structure.html", error="Please provide a URL.")
        if not start_url.startswith("http"):
            start_url = "http://" + start_url

        # Store the search history in the database
        u_id = session.get('user_id')
        usage_tool = "Site Structure"
        add_search_history(u_id, usage_tool, start_url)

        # Create a unique ID for this crawl job
        job_id = str(uuid.uuid4())
        session['job_id'] = job_id
        crawl_status[job_id] = {
            'status': 'running',
            'progress': 0,
            'url': start_url,
            'start_time': time.time()
        }
        
        # Run the crawler in a background thread
        try:
            executor.submit(run_async_in_thread_with_progress, main_crawl(start_url, job_id), job_id)
        except Exception as e:
            print(f"Error during crawling: {e}")
            crawl_status[job_id]['status'] = 'failed'
            return render_template("site_structure.html", error="An error occurred while crawling the URL.")
        
        return redirect(url_for("loading"))
    
    return render_template("site_structure.html")


def run_async_in_thread_with_progress(coro, job_id):
    """Run an async coroutine in a thread and update progress"""
    try:
        result = run_async_in_thread(coro)
        crawl_status[job_id]['status'] = 'completed'
        crawl_status[job_id]['progress'] = 100
        return result
    except Exception as e:
        print(f"Error in background task: {e}")
        crawl_status[job_id]['status'] = 'failed'
        return None


@app.route("/loading")
@login_required
@subscription_required_with_tokens(2)
def loading():
    job_id = session.get('job_id')
    if not job_id or job_id not in crawl_status:
        return redirect(url_for("site_structure"))
        
    return render_template("loading.html", job_id=job_id)


@app.route("/progress/<job_id>")
def progress(job_id):
    if job_id not in crawl_status:
        return jsonify({"status": "unknown"})
        
    status_data = crawl_status[job_id]
    
    # Calculate elapsed time
    elapsed = time.time() - status_data['start_time']
    
    # Simulate progress if we don't have real metrics
    if status_data['status'] == 'running' and status_data['progress'] < 95:
        # Gradually increase progress - exponentially slower as it approaches 95%
        progress_increment = max(0.5, 10 * (1 - status_data['progress']/100))
        status_data['progress'] += progress_increment
        
    return jsonify({
        "status": status_data['status'],
        "progress": min(round(status_data['progress'], 1), 100),
        "elapsed": round(elapsed, 1),
        "url": status_data['url']
    })


@app.route("/visualize")
@login_required
def visualize():
    user_id = session.get('user_id')
    job_id = session.get('job_id')
    
    app.logger.info(f"Visualize page requested for job_id: {job_id} by user: {user_id}")
    
    if not job_id:
        app.logger.warning("No job_id in session, redirecting to site_structure")
        flash("No crawl job found. Please start a new crawl.", "warning")
        return redirect(url_for("site_structure"))
    
    # **ENHANCED STATUS CHECKING**
    if job_id in crawl_status:
        status = crawl_status[job_id]['status']
        progress = crawl_status[job_id].get('progress', 0)
        app.logger.info(f"Crawl status for {job_id}: {status} ({progress}%)")
        
        if status == 'running':
            app.logger.info("Crawl still running, redirecting to loading page")
            return redirect(url_for("loading"))
        elif status == 'failed':
            app.logger.error("Crawl failed, redirecting to site_structure")
            flash("Crawl failed. Please try again.", "danger")
            return redirect(url_for("site_structure"))
    
    # **CHECK IF DATA FILE EXISTS**
    crawled_data = f"crawled_data/crawl_{job_id}.json"
    if not os.path.exists(crawled_data):
        app.logger.warning(f"Data file missing: {crawled_data}")
        flash("Crawl data not found. Please start a new crawl.", "warning")
        return redirect(url_for("site_structure"))
    
    app.logger.info("Rendering visualize.html")
    return render_template("visualize.html", job_id=job_id)

@app.route("/data")
@csrf_exempt
def get_data():
    """Return crawl data as JSON with enhanced error handling."""
    try:
        # Check if user has session and is logged in
        user_id = session.get('user_id')
        if not user_id:
            app.logger.warning("No user_id in session for data request")
            return jsonify({
                "error": "Authentication required",
                "home_links": {},
                "status_codes": {},
                "other_links": {}
            }), 401
        
        job_id = session.get('job_id')
        app.logger.info(f"Data request for job_id: {job_id} by user: {user_id}")
        
        if not job_id:
            app.logger.warning("No job_id in session for data request")
            return jsonify({
                "error": "No crawl job found. Please start a new crawl.",
                "home_links": {},
                "status_codes": {},
                "other_links": {},
                "redirect": "/site_structure"  # **ADD REDIRECT INFO**
            }), 404
        
        # **ENHANCED CRAWL STATUS CHECK**
        if job_id in crawl_status:
            status = crawl_status[job_id]['status']
            progress = crawl_status[job_id].get('progress', 0)
            app.logger.info(f"Crawl status for {job_id}: {status} ({progress}%)")
            
            if status == 'running':
                return jsonify({
                    "error": "Crawl still in progress",
                    "status": "running",
                    "progress": progress,
                    "message": f"Crawl is {progress}% complete. Please wait...",
                    "redirect": "/loading"  # **ADD REDIRECT INFO**
                }), 202
            elif status == 'failed':
                return jsonify({
                    "error": "Crawl failed",
                    "status": "failed",
                    "message": "The website crawl failed. Please try again.",
                    "redirect": "/site_structure"  # **ADD REDIRECT INFO**
                }), 500
        
        # **ENHANCED FILE EXISTENCE CHECK**
        crawled_data_path = f"crawled_data/crawl_{job_id}.json"
        app.logger.info(f"Looking for data file: {crawled_data_path}")
        
        if not os.path.exists(crawled_data_path):
            app.logger.warning(f"Data file missing: {crawled_data_path}")
            
            # **WAIT A BIT FOR FILE TO BE WRITTEN**
            import time
            for i in range(3):  # Wait up to 3 seconds
                time.sleep(1)
                if os.path.exists(crawled_data_path):
                    break
            
            if not os.path.exists(crawled_data_path):
                return jsonify({
                    "error": "Crawl data not found",
                    "message": "The crawl data file is missing. Please start a new crawl.",
                    "redirect": "/site_structure",
                    "debug_info": {
                        "job_id": job_id,
                        "expected_file": crawled_data_path
                    }
                }), 404
        
        # **ENHANCED FILE SIZE CHECK**
        try:
            file_size = os.path.getsize(crawled_data_path)
            if file_size == 0:
                app.logger.error(f"Data file is empty: {crawled_data_path}")
                return jsonify({
                    "error": "Empty crawl data",
                    "message": "The crawl data file is empty. Please start a new crawl.",
                    "redirect": "/site_structure"
                }), 500
        except Exception as e:
            app.logger.error(f"Error checking file size: {str(e)}")
        
        # Load the actual data
        data = load_results()
        
        # **ENHANCED DATA VALIDATION**
        if not data or not isinstance(data, dict):
            app.logger.error(f"Invalid data structure loaded for job {job_id}")
            return jsonify({
                "error": "Invalid data structure",
                "message": "The crawl data is corrupted. Please start a new crawl.",
                "home_links": {},
                "status_codes": {},
                "other_links": {},
                "redirect": "/site_structure"
            }), 500
        
        # Ensure required keys exist with defaults
        home_links = data.get("home_links", {})
        status_codes = data.get("status_codes", {})
        other_links = data.get("other_links", {})
        
        # **VALIDATE DATA IS NOT EMPTY**
        if not home_links and not other_links:
            app.logger.warning(f"No link data found for job {job_id}")
            return jsonify({
                "error": "No crawl data found",
                "message": "The crawl completed but found no links. The website might be inaccessible or have no content.",
                "home_links": {},
                "status_codes": {},
                "other_links": {},
                "redirect": "/site_structure"
            }), 404
        
        # Log data summary
        home_links_count = len(home_links)
        status_codes_count = len(status_codes)
        other_links_count = len(other_links)
        
        app.logger.info(f"Returning data for job {job_id}: {home_links_count} home links, {status_codes_count} status codes, {other_links_count} other links")
        
        # Build response
        response_data = {
            "home_links": home_links,
            "status_codes": status_codes,
            "other_links": other_links,
            "domain": data.get("domain", ""),
            "status": "success",
            "summary": {
                "home_links_count": home_links_count,
                "status_codes_count": status_codes_count,
                "other_links_count": other_links_count,
                "job_id": job_id
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"Error in get_data: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}",
            "message": "An unexpected error occurred while loading the data.",
            "home_links": {},
            "status_codes": {},
            "other_links": {},
            "redirect": "/site_structure"
        }), 500

def get_active_subscription_id(user_id):
    """Helper to get active subscription ID"""
    subscription = SubscribedUser.query.filter(
        SubscribedUser.U_ID == user_id,
        SubscribedUser.end_date > datetime.now(UTC),
        SubscribedUser._is_active == True
    ).first()
    return subscription.id if subscription else None

@app.route('/download_results')
def download_results():
    # Retrieve the crawl job ID from the session
    job_id = session.get('job_id')
    if not job_id:
        flash("No crawl job found. Please start a new crawl and upload the files again.")
        return redirect(url_for('site_structure'))

    # Build the CSV file path using the job ID
    csv_path = f"crawled_data/crawl_{job_id}.csv"
    
    if not os.path.exists(csv_path):
        flash("Crawl results file not found or expired. Please start a new crawl and upload the files again.")
        return redirect(url_for('site_structure'))
    
    return send_file(csv_path, mimetype='text/csv', as_attachment=True, download_name=f'crawl_results_{job_id}.csv')

async def main_crawl(start_url, job_id):
    """Run the crawler asynchronously and save results with the job ID."""
    url_status, home_links, other_links = await crawl(start_url)
    save_to_json(url_status, home_links, other_links, job_id)

# Register the custom test
@app.template_test('match')
def match_test(value, pattern):
    return re.search(pattern, value) is not None

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name')
            email = request.form.get('email')
            message = request.form.get('message')
            
            # Validate required fields
            if not all([name, email, message]):
                flash('Please fill in all required fields.', 'warning')
                return render_template('contact.html')
            
            # ✅ SAVE TO DATABASE FIRST
            contact_submission = ContactSubmission(
                name=name,
                email=email,
                message=message,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            
            db.session.add(contact_submission)
            db.session.commit()
            
            # Then send emails (your existing code)
            subject = f"Web Analyzer Pro Contact Form: {name}"
            msg = Message(
                subject=subject,
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']]
            )
            
            # Include submission ID in email for tracking
            msg.body = f"""
            Contact Form Submission (ID: {contact_submission.id}):
            
            Name: {name}
            Email: {email}
            IP Address: {request.remote_addr}
            Submitted: {contact_submission.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
            
            Message:
            {message}
            """
            
            mail.send(msg)
            
            # Send auto-reply
            auto_reply = Message(
                subject="Thank you for contacting Web Analyzer Pro",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            
            auto_reply.body = f"""
            Dear {name},
            
            Thank you for contacting Web Analyzer Pro. We have received your message (Reference ID: {contact_submission.id}) and will get back to you as soon as possible, typically within 24 hours during business days.
            
            For urgent inquiries, please call our support line at +1 (800) 123-4567.
            
            Best Regards,
            The Web Analyzer Pro Team
            """
            
            mail.send(auto_reply)
            
            flash('contact:Your message has been sent successfully! We will contact you soon.', 'success')
            return redirect(url_for('contact'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error processing contact form: {str(e)}")
            flash('There was an error sending your message. Please try again later.', 'danger')
            
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')
@app.route('/terms')
def terms():
    return render_template('terms.html')
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/cookie-policy')
def cookie_policy():
    return render_template('cookie_policy.html')

@app.route('/time-date')
def time_and_date_today():
    current_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"current_time": current_time})

# Register the custom test
@app.template_test('match')
def match_test(value, pattern):
    return re.search(pattern, value) is not None
# Add these custom filters to your app.py file after the app initialization



@app.template_filter('parse_json_features')
def parse_json_features(features_str):
    """
    Parse JSON features string and return a dictionary
    or list of features for display
    """
    if not features_str:
        return []
    
    # Remove any extra whitespace
    features_str = features_str.strip()
    
    # Try to parse as JSON
    try:
        # If it's a JSON object
        if features_str.startswith('{') and features_str.endswith('}'):
            features_dict = json.loads(features_str)
            # Convert to list of tuples for easier template iteration
            return [(key, value) for key, value in features_dict.items()]
        # If it's a comma-separated list
        else:
            return [(feature.strip(), True) for feature in features_str.split(',') if feature.strip()]
    except (json.JSONDecodeError, AttributeError):
        # Fallback to treating as comma-separated string
        try:
            return [(feature.strip(), True) for feature in features_str.split(',') if feature.strip()]
        except:
            return []

@app.template_filter('format_feature_name')
def format_feature_name(name):
    """
    Format feature names for display
    Examples:
    - 'feature1' -> 'Feature 1'
    - 'some_feature' -> 'Some Feature'
    - 'feature1' -> 'Feature 1'
    - 'feature2' -> 'Feature 2'
    """
    if not name:
        return ''
    
    # Convert to string if not already
    name = str(name)
    
    # Handle special patterns like 'feature1', 'feature2' etc.
    if name.startswith('feature') and len(name) > 7 and name[-1].isdigit():
        # Extract the number
        match = re.match(r'feature(\d+)', name)
        if match:
            num = match.group(1)
            return f'Feature {num}'
    
    # Replace underscores with spaces
    name = name.replace('_', ' ')
    
    # Replace camelCase with spaces (e.g., 'someFeature' -> 'some Feature')
    name = re.sub('([a-z])([A-Z])', r'\1 \2', name)
    
    # Capitalize first letter of each word
    name = ' '.join(word.capitalize() for word in name.split())
    
    return name.strip()

@app.template_filter('feature_icon')
def feature_icon(value):
    """
    Return appropriate icon class based on feature value
    """
    if value is True or str(value).lower() == 'true':
        return 'fa-check-circle text-secondary'
    elif value is False or str(value).lower() == 'false':
        return 'fa-times-circle text-gray-400'
    else:
        # For non-boolean values, always show check
        return 'fa-check-circle text-secondary'

@app.template_filter('format_feature')
def format_feature(value):
    """
    Format the display of a feature based on its value
    """
    if isinstance(value, bool):
        # For boolean values, we just use the icon
        return ''
    elif isinstance(value, (int, float)):
        # Continue with number formatting...
        return str(value)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Add this function to your app.py file to clean up duplicate subscriptions

def cleanup_duplicate_subscriptions():
    """
    Utility function to clean up duplicate active subscriptions for users.
    Keeps only the most recent active subscription per user.
    """
    from sqlalchemy import and_
    
    # Get current time
    now = datetime.now(UTC)
    
    # Get all users
    users = User.query.all()
    
    deactivated_count = 0
    
    for user in users:
        # Get all active subscriptions for this user
        active_subscriptions = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user.id)
            .filter(SubscribedUser.end_date > now)
            .filter(SubscribedUser._is_active == True)
            .order_by(SubscribedUser.start_date.desc())  # Changed from created_at to start_date
            .all()
        )
        
        # If user has more than one active subscription
        if len(active_subscriptions) > 1:
            # Keep the first (most recent) one, deactivate the rest
            for sub in active_subscriptions[1:]:
                sub.is_active = False
                deactivated_count += 1
                app.logger.info(f"Deactivated duplicate subscription {sub.id} for user {user.id}")
    
    if deactivated_count > 0:
        db.session.commit()
        app.logger.info(f"Cleaned up {deactivated_count} duplicate subscriptions")
    
    return deactivated_count
    

def fix_user_timestamps():
    """Fix NULL timestamps for existing users"""
    with app.app_context():
        users = User.query.all()
        current_time = datetime.now()
        
        for user in users:
            updated = False
            
            # Set last_login_at if NULL
            if user.last_login_at is None:
                user.last_login_at = user.created_at or current_time
                updated = True
            
            # Set profile_updated_at if NULL  
            if user.profile_updated_at is None:
                user.profile_updated_at = user.created_at or current_time
                updated = True
            
            # Set password_changed_at if NULL
            if user.password_changed_at is None:
                user.password_changed_at = user.created_at or current_time
                updated = True
            
            if updated:
                print(f"Updated timestamps for user: {user.company_email}")
        
        try:
            db.session.commit()
            print("Successfully updated all user timestamps")
        except Exception as e:
            db.session.rollback()
            print(f"Error updating timestamps: {str(e)}")

# ----------------------
# Automatic Crawl Data Cleanup Functions
# ----------------------

def cleanup_old_crawl_data(days_to_keep=7):
    """
    Delete crawl data files older than specified days
    
    Args:
        days_to_keep (int): Number of days to keep crawl data (default: 7)
    
    Returns:
        int: Number of files deleted
    """
    try:
        crawl_data_dir = "crawled_data"
        deleted_count = 0
        
        # Create directory if it doesn't exist
        if not os.path.exists(crawl_data_dir):
            os.makedirs(crawl_data_dir, exist_ok=True)
            app.logger.info("Created crawled_data directory")
            return 0
        
        # Calculate cutoff time (files older than this will be deleted)
        cutoff_time = time.time() - (days_to_keep * 24 * 60 * 60)
        
        # Get all crawl files (both JSON and CSV)
        crawl_files = glob.glob(os.path.join(crawl_data_dir, 'crawl_*.json'))
        crawl_files.extend(glob.glob(os.path.join(crawl_data_dir, 'crawl_*.csv')))
        
        for file_path in crawl_files:
            try:
                # Get file modification time
                file_mtime = os.path.getmtime(file_path)
                
                # Delete if older than cutoff time
                if file_mtime < cutoff_time:
                    filename = os.path.basename(file_path)
                    os.remove(file_path)
                    deleted_count += 1
                    app.logger.info(f"Deleted old crawl file: {filename}")
                    
                    # Extract job_id from filename and clean up from crawl_status
                    if filename.startswith('crawl_') and '.' in filename:
                        job_id = filename.split('crawl_')[1].split('.')[0]
                        if job_id in crawl_status:
                            del crawl_status[job_id]
                            app.logger.info(f"Cleaned up crawl_status for job: {job_id}")
                            
            except Exception as e:
                app.logger.error(f"Error deleting file {file_path}: {str(e)}")
        
        # Also cleanup old entries from crawl_status (in case files were manually deleted)
        current_time = time.time()
        old_jobs = []
        
        for job_id, status_data in crawl_status.items():
            job_age = current_time - status_data.get('start_time', current_time)
            if job_age > (days_to_keep * 24 * 60 * 60):
                old_jobs.append(job_id)
        
        for job_id in old_jobs:
            del crawl_status[job_id]
            app.logger.info(f"Cleaned up old crawl_status entry: {job_id}")
        
        if deleted_count > 0 or old_jobs:
            app.logger.info(f"Cleanup completed. Deleted {deleted_count} files and {len(old_jobs)} status entries")
        else:
            app.logger.debug("No old crawl data found to clean up")
            
        return deleted_count
        
    except Exception as e:
        app.logger.error(f"Error during crawl data cleanup: {str(e)}")
        return 0

def cleanup_crawl_status_memory():
    """
    Clean up completed/failed crawl jobs from memory that are older than 1 hour
    This prevents memory buildup from the crawl_status dictionary
    """
    try:
        current_time = time.time()
        old_jobs = []
        
        for job_id, status_data in crawl_status.items():
            # Remove completed/failed jobs older than 1 hour
            job_age = current_time - status_data.get('start_time', current_time)
            job_status = status_data.get('status', 'unknown')
            
            if job_status in ['completed', 'failed'] and job_age > 3600:  # 1 hour = 3600 seconds
                old_jobs.append(job_id)
        
        cleaned_count = 0
        for job_id in old_jobs:
            del crawl_status[job_id]
            cleaned_count += 1
        
        if cleaned_count > 0:
            app.logger.info(f"Cleaned up {cleaned_count} old crawl status entries from memory")
            
        return cleaned_count
        
    except Exception as e:
        app.logger.error(f"Error cleaning up crawl status memory: {str(e)}")
        return 0

def setup_daily_cleanup_scheduler():
    """
    Set up daily cleanup scheduler using APScheduler
    """
    try:
        # Create scheduler
        scheduler = BackgroundScheduler()
        
        # Add daily cleanup job at 2:00 AM
        scheduler.add_job(
            func=cleanup_old_crawl_data,
            trigger="cron",
            hour=2,
            minute=0,
            id='daily_crawl_cleanup',
            max_instances=1,  # Prevent multiple instances running simultaneously
            coalesce=True,    # If a job was missed, run it only once when possible
            kwargs={'days_to_keep': 7}  # Keep files for 7 days
        )
        
        # Add hourly memory cleanup job
        scheduler.add_job(
            func=cleanup_crawl_status_memory,
            trigger="cron",
            minute=0,  # Run every hour at minute 0
            id='hourly_memory_cleanup',
            max_instances=1,
            coalesce=True
        )
        
        # Start the scheduler
        scheduler.start()
        app.logger.info("Daily crawl data cleanup scheduler started")
        app.logger.info("- Daily file cleanup: 2:00 AM (keeps files for 7 days)")
        app.logger.info("- Hourly memory cleanup: every hour")
        
        # Shut down the scheduler when exiting the app
        atexit.register(lambda: scheduler.shutdown())
        
        return scheduler
        
    except Exception as e:
        app.logger.error(f"Error setting up cleanup scheduler: {str(e)}")
        return None

def get_available_tokens(user_id):
    """
    Get the number of tokens available for a user today
    
    Returns:
        dict: {'available': int, 'total': int, 'used': int}
    """
    now = datetime.now(UTC)
    active_subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > now)
        .filter(SubscribedUser._is_active == True)
        .first()
    )
    
    if not active_subscription:
        return {'available': 0, 'total': 0, 'used': 0}
    
    # Apply daily reset logic
    today = datetime.now(UTC).date()
    last_reset_date = getattr(active_subscription, 'last_usage_reset', None)
    
    if not last_reset_date or last_reset_date.date() < today:
        active_subscription.current_usage = 0
        active_subscription.last_usage_reset = datetime.now(UTC)
        try:
            db.session.commit()
        except:
            db.session.rollback()
    
    total_tokens = active_subscription.subscription.usage_per_day
    used_tokens = active_subscription.current_usage
    available_tokens = max(0, total_tokens - used_tokens)
    
    return {
        'available': available_tokens,
        'total': total_tokens,
        'used': used_tokens
    }

# Add these utility functions to your app.py file (after imports, before routes)

def store_search_results(search_type, url, home_links, other_links, robots_info):
    """Standardize how search results are stored in session"""
    try:
        session[f'{search_type}_url'] = url
        session[f'{search_type}_home_links'] = home_links
        session[f'{search_type}_other_links'] = other_links
        if robots_info and 'parser_id' in robots_info:
            session_robots_info = robots_info.copy()
            session_robots_info.pop('parser_id', None)
            session[f'{search_type}_robots_info'] = session_robots_info
        session.modified = True
    except Exception as e:
        app.logger.error(f"Error storing search results: {str(e)}")

def get_search_results(search_type):
    """Standardize how search results are retrieved from session"""
    try:
        url = session.get(f'{search_type}_url', '')
        home_links = session.get(f'{search_type}_home_links', [])
        other_links = session.get(f'{search_type}_other_links', [])
        robots_info = session.get(f'{search_type}_robots_info')
        
        links_data = None
        if home_links or other_links:
            links_data = {'home': home_links, 'other': other_links}
        
        return url, links_data, robots_info
    except Exception as e:
        app.logger.error(f"Error retrieving search results: {str(e)}")
        return '', None, None

def clear_search_results(search_type):
    """Clear search results for a specific search type"""
    try:
        session.pop(f'{search_type}_url', None)
        session.pop(f'{search_type}_home_links', None)
        session.pop(f'{search_type}_other_links', None)
        session.pop(f'{search_type}_robots_info', None)
        session.modified = True
    except Exception as e:
        app.logger.error(f"Error clearing search results: {str(e)}")

def debug_link_analysis(url, home_links, other_links, robots_info):
    """Debug function to log link analysis results"""
    try:
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc.lower().replace('www.', '')
        
        app.logger.info(f"=== Link Analysis Debug for {url} ===")
        app.logger.info(f"Base domain: {base_domain}")
        app.logger.info(f"Home links count: {len(home_links)}")
        app.logger.info(f"Other links count: {len(other_links)}")
        app.logger.info(f"Robots info available: {robots_info is not None}")
        
        if len(home_links) == 0:
            app.logger.warning(f"WARNING: No home links found for {url}")
            
        # Log first few home links for debugging
        for i, link in enumerate(home_links[:5]):
            app.logger.info(f"Home link {i+1}: {link}")
            
        # Log first few other links for debugging
        for i, link in enumerate(other_links[:5]):
            app.logger.info(f"Other link {i+1}: {link}")
            
    except Exception as e:
        app.logger.error(f"Error in debug_link_analysis: {str(e)}")

def safe_analyze_links(url, respect_robots=True):
    """
    Safe wrapper around analyze_links with comprehensive error handling
    """
    try:
        app.logger.info(f"Starting safe link analysis for: {url}")
        
        # Call the main analyze_links function with correct signature
        home_links, other_links, robots_info = analyze_links(
            url=url,
            respect_robots=respect_robots
        )
        
        # Debug the results
        debug_link_analysis(url, home_links, other_links, robots_info)
        
        return home_links, other_links, robots_info
        
    except Exception as e:
        app.logger.error(f"Error in safe_analyze_links: {str(e)}")
        app.logger.error(f"Exception details: {traceback.format_exc()}")
        return [], [], None

def is_same_domain(url1, url2):
    """Enhanced domain comparison with better handling of edge cases"""
    try:
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        
        # Normalize domains
        domain1 = parsed1.netloc.lower()
        domain2 = parsed2.netloc.lower()
        
        # Remove www. prefix
        if domain1.startswith('www.'):
            domain1 = domain1[4:]
        if domain2.startswith('www.'):
            domain2 = domain2[4:]
            
        # Remove port numbers for comparison
        domain1 = domain1.split(':')[0]
        domain2 = domain2.split(':')[0]
        
        return domain1 == domain2
        
    except Exception as e:
        app.logger.error(f"Error comparing domains {url1} and {url2}: {str(e)}")
        return False

# Add this test route for debugging (REMOVE IN PRODUCTION)
@app.route('/test_analyze_links')
@login_required
def test_analyze_links():
    """Test route to verify analyze_links is working (REMOVE IN PRODUCTION)"""
    test_url = request.args.get('url', 'https://httpbin.org/links/5')
    
    try:
        app.logger.info(f"Testing analyze_links with URL: {test_url}")
        
        # Test the function with debug logging
        home_links, other_links, robots_info = safe_analyze_links(test_url)
        
        return jsonify({
            'test_url': test_url,
            'home_links_count': len(home_links),
            'other_links_count': len(other_links),
            'home_links_sample': home_links[:3],
            'other_links_sample': other_links[:3],
            'robots_info_available': robots_info is not None,
            'robots_success': robots_info.get('success', False) if robots_info else False,
            'test_status': 'SUCCESS'
        })
        
    except Exception as e:
        app.logger.error(f"Error in test_analyze_links: {str(e)}")
        return jsonify({
            'test_url': test_url,
            'error': str(e),
            'test_status': 'FAILED'
        }), 500
    

import hashlib
import time

def generate_cache_key(user_id, search_type, url):
    """Generate a unique cache key for search results"""
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    return f"search_{user_id}_{search_type}_{url_hash}"

def store_search_results(search_type, url, home_links, other_links, robots_info):
    """Store search results in cache instead of session"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return False
            
        cache_key = generate_cache_key(user_id, search_type, url)
        
        # Store in cache with 2 hour expiration
        cache_data = {
            'url': url,
            'home_links': home_links,
            'other_links': other_links,
            'robots_info': robots_info.copy() if robots_info else None,
            'timestamp': time.time()
        }
        
        # Remove parser_id if present (not serializable)
        if cache_data['robots_info'] and 'parser_id' in cache_data['robots_info']:
            cache_data['robots_info'].pop('parser_id', None)
        
        cache.set(cache_key, cache_data, timeout=7200)  # 2 hours
        
        # Store only the cache key in session (much smaller)
        session[f'{search_type}_cache_key'] = cache_key
        session.modified = True
        
        app.logger.info(f"Stored search results in cache: {cache_key}")
        return True
        
    except Exception as e:
        app.logger.error(f"Error storing search results in cache: {str(e)}")
        return False

def get_search_results(search_type):
    """Get search results from cache"""
    try:
        cache_key = session.get(f'{search_type}_cache_key')
        if not cache_key:
            return '', None, None
            
        cache_data = cache.get(cache_key)
        if not cache_data:
            # Cache expired or missing
            session.pop(f'{search_type}_cache_key', None)
            return '', None, None
            
        url = cache_data.get('url', '')
        home_links = cache_data.get('home_links', [])
        other_links = cache_data.get('other_links', [])
        robots_info = cache_data.get('robots_info')
        
        links_data = None
        if home_links or other_links:
            links_data = {'home': home_links, 'other': other_links}
        
        return url, links_data, robots_info
        
    except Exception as e:
        app.logger.error(f"Error retrieving search results from cache: {str(e)}")
        return '', None, None

def clear_search_results(search_type):
    """Clear search results from cache"""
    try:
        cache_key = session.get(f'{search_type}_cache_key')
        if cache_key:
            cache.delete(cache_key)
            app.logger.info(f"Cleared cache: {cache_key}")
        session.pop(f'{search_type}_cache_key', None)
        session.modified = True
    except Exception as e:
        app.logger.error(f"Error clearing search results: {str(e)}")

def store_simple_data(key, data, timeout=3600):
    """Store simple data in cache (for non-search related data)"""
    try:
        user_id = session.get('user_id')
        cache_key = f"user_{user_id}_{key}"
        cache.set(cache_key, data, timeout=timeout)
        session[f'{key}_cache_key'] = cache_key
        session.modified = True
        return True
    except Exception as e:
        app.logger.error(f"Error storing simple data: {str(e)}")
        return False

def get_simple_data(key):
    """Get simple data from cache"""
    try:
        cache_key = session.get(f'{key}_cache_key')
        if not cache_key:
            return None
        return cache.get(cache_key)
    except Exception as e:
        app.logger.error(f"Error getting simple data: {str(e)}")
        return None
    
def normalize_existing_admin_emails():
    """
    Normalize existing admin email addresses to lowercase and remove duplicates
    """
    try:
        with app.app_context():
            # Get all admin records
            all_admins = Admin.query.all()
            normalized_emails = {}
            duplicates_found = []
            
            for admin in all_admins:
                original_email = admin.email_id
                normalized_email = original_email.lower().strip()
                
                if normalized_email in normalized_emails:
                    # Found a duplicate
                    existing_admin = normalized_emails[normalized_email]
                    duplicates_found.append({
                        'existing': existing_admin,
                        'duplicate': admin,
                        'email': normalized_email
                    })
                    print(f"⚠  Duplicate found: {original_email} (ID: {admin.id}) conflicts with {existing_admin.email_id} (ID: {existing_admin.id})")
                else:
                    # Update email to normalized version
                    admin.email_id = normalized_email
                    normalized_emails[normalized_email] = admin
                    
                    if original_email != normalized_email:
                        print(f"✅ Normalized: {original_email} → {normalized_email}")
            
            # Handle duplicates (keep the one created first, remove others)
            for dup_info in duplicates_found:
                existing_admin = dup_info['existing']
                duplicate_admin = dup_info['duplicate']
                
                # Keep the one created earlier
                if existing_admin.created_at <= duplicate_admin.created_at:
                    print(f"🗑  Removing duplicate admin: {duplicate_admin.NAME} ({duplicate_admin.email_id}) ID: {duplicate_admin.id}")
                    db.session.delete(duplicate_admin)
                else:
                    print(f"🗑  Removing duplicate admin: {existing_admin.NAME} ({existing_admin.email_id}) ID: {existing_admin.id}")
                    db.session.delete(existing_admin)
                    # Update the normalized_emails dict
                    normalized_emails[dup_info['email']] = duplicate_admin
            
            # Commit all changes
            db.session.commit()
            print(f"✅ Successfully normalized {len(all_admins)} admin email addresses")
            print(f"🗑  Removed {len(duplicates_found)} duplicate admin accounts")
            
            return len(duplicates_found)
            
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error normalizing admin emails: {str(e)}")
        app.logger.error(f"Error normalizing admin emails: {str(e)}")
        return -1
@app.route('/purchase_tokens', methods=['POST'])
@login_required
@csrf.exempt
def purchase_tokens():
    """Initialize token purchase process"""
    try:
        user_id = session.get('user_id')
        token_count = int(request.form.get('token_count', 0))
        
        # Validate token count
        valid_token_counts = [10, 25, 50, 100]
        if token_count not in valid_token_counts:
            return jsonify({'error': 'Invalid token count'}), 400
        
        # Check if user has active subscription
        active_subscription = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date > datetime.now(UTC))
            .filter(SubscribedUser._is_active == True)
            .first()
        )
        
        if not active_subscription:
            return jsonify({'error': 'No active subscription found'}), 400
        
        # Calculate pricing (₹2 per token including GST)
        price_per_token = 2.00
        total_amount = token_count * price_per_token
        gst_rate = 0.18
        base_amount = total_amount / (1 + gst_rate)
        gst_amount = total_amount - base_amount
        
        # Create Razorpay order
        razorpay_order = razorpay_client.order.create({
            'amount': int(total_amount * 100),  # Amount in paisa
            'currency': 'INR',
            'payment_capture': '1',
            'notes': {
                'user_id': user_id,
                'subscription_id': active_subscription.id,
                'token_count': token_count,
                'type': 'token_purchase'
            }
        })
        
        # Store token purchase record
        token_purchase = TokenPurchase(
            user_id=user_id,
            subscription_id=active_subscription.id,
            token_count=token_count,
            base_amount=base_amount,
            gst_amount=gst_amount,
            total_amount=total_amount,
            razorpay_order_id=razorpay_order['id'],
            status='created'
        )
        
        db.session.add(token_purchase)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'order_id': razorpay_order['id'],
            'amount': total_amount,
            'token_count': token_count,
            'razorpay_key': app.config['RAZORPAY_KEY_ID']
        })
        
    except Exception as e:
        app.logger.error(f"Error in purchase_tokens: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    
# Replace the existing verify_token_payment function in app.py (around line 2850)

@app.route('/verify_token_payment', methods=['POST'])
@login_required
@csrf.exempt
def verify_token_payment():
    """Verify token payment and add tokens to user account"""
    try:
        user_id = session.get('user_id')
        razorpay_payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = request.form.get('razorpay_order_id')
        razorpay_signature = request.form.get('razorpay_signature')
        
        # Get user object first - THIS WAS MISSING!
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Validate signature
        signature_valid = verify_razorpay_signature(
            razorpay_order_id, 
            razorpay_payment_id, 
            razorpay_signature, 
            app.config['RAZORPAY_KEY_SECRET']
        )
        
        if not signature_valid:
            return jsonify({'error': 'Payment verification failed'}), 400
        
        # Find the token purchase record
        token_purchase = TokenPurchase.query.filter_by(
            razorpay_order_id=razorpay_order_id,
            user_id=user_id,
            status='created'
        ).first()
        
        if not token_purchase:
            return jsonify({'error': 'Token purchase record not found'}), 404
        
        # Verify payment with Razorpay
        try:
            payment_details = razorpay_client.payment.fetch(razorpay_payment_id)
            
            if payment_details['status'] not in ['authorized', 'captured']:
                return jsonify({'error': 'Payment not authorized'}), 400
                
            expected_amount = int(token_purchase.total_amount * 100)
            if payment_details['amount'] != expected_amount:
                return jsonify({'error': 'Amount mismatch'}), 400
                
        except Exception as e:
            app.logger.error(f"Razorpay verification error: {str(e)}")
            return jsonify({'error': 'Payment verification failed'}), 400
        
        # Update token purchase record with invoice details
        token_purchase.razorpay_payment_id = razorpay_payment_id
        token_purchase.status = 'completed'
        token_purchase._generate_invoice_details()  # Generate invoice number and date
        
        # Get user's active subscription
        active_subscription = SubscribedUser.query.get(token_purchase.subscription_id)
        
        # Create user token record
        user_token = UserToken(
            user_id=user_id,
            subscription_id=active_subscription.id,
            purchase_id=token_purchase.id,
            tokens_purchased=token_purchase.token_count,
            tokens_used=0,
            tokens_remaining=token_purchase.token_count,
            expires_at=datetime.now(UTC) + timedelta(days=365)
        )
        
        db.session.add(user_token)
        
        # Send confirmation email - NOW WITH PROPER USER OBJECT
        email_sent = False
        try:
            send_token_purchase_confirmation_email(user, token_purchase)
            app.logger.info(f"Token purchase confirmation email sent to {user.company_email}")
            email_sent = True
        except Exception as email_error:
            # Log email error but don't fail the transaction
            app.logger.error(f"Failed to send token purchase confirmation email: {str(email_error)}")
            # Log the full traceback for debugging
            import traceback
            app.logger.error(f"Email error traceback: {traceback.format_exc()}")
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully purchased {token_purchase.token_count} additional tokens!',
            'invoice_number': token_purchase.invoice_number,
            'email_sent': email_sent
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in verify_token_payment: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
# 5. Add token invoice generation
def generate_token_invoice_pdf(token_purchase):
    """
    Generate PDF invoice for token purchase
    """
    from io import BytesIO
    import os
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch, mm
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
    from num2words import num2words

    # Define brand colors to match the logo
    brand_color = colors.Color(0.73, 0.20, 0.04)
    secondary_color = colors.Color(0.95, 0.95, 0.95)
    text_color = colors.Color(0.25, 0.25, 0.25)

    # Prepare buffer and document
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=A4, 
        leftMargin=12*mm, 
        rightMargin=12*mm, 
        topMargin=12*mm, 
        bottomMargin=12*mm
    )
    
    # Create custom styles (same as regular invoice)
    invoice_title_style = ParagraphStyle(
        name='InvoiceTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=16,
        alignment=TA_RIGHT,
        textColor=brand_color,
        spaceAfter=4
    )
    
    section_title_style = ParagraphStyle(
        name='SectionTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=text_color,
        spaceAfter=2
    )
    
    normal_style = ParagraphStyle(
        name='NormalCustom',
        fontName='Helvetica',
        fontSize=8,
        textColor=text_color,
        leading=10
    )

    elements = []
    
    # Logo and Title
    logo_path = os.path.join('assert', '4d-logo.webp')
    
    try:
        logo = Image(logo_path, width=1.5*inch, height=0.75*inch)
        header_data = [[
            logo, 
            Paragraph("TAX INVOICE - TOKEN PURCHASE", invoice_title_style)
        ]]
        
        header_table = Table(header_data, colWidths=[doc.width/2, doc.width/2])
        header_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(header_table)
    except:
        elements.append(Paragraph("TAX INVOICE - TOKEN PURCHASE", invoice_title_style))
    
    elements.append(Spacer(1, 10))
    
    # Company Details
    company_details = [
        [Paragraph("<b>Company Name:</b>", section_title_style)],
        [Paragraph("M/s. Fourth Dimension Media Solutions Pvt Ltd", normal_style)],
        [Paragraph("State & Code: Tamil Nadu (33)", normal_style)],
        [Paragraph("GSTIN: 33AABCF6993P1ZY", normal_style)],
        [Paragraph("PAN: AABCF6993P", normal_style)],
        [Paragraph("CIN: U22130TN2011PTC079276", normal_style)]
    ]
    
    company_table = Table(company_details, colWidths=[doc.width])
    elements.append(company_table)
    elements.append(Spacer(1, 10))
    
    # Bill To and Invoice Details
    user = token_purchase.user
    bill_to_content = [
        [Paragraph("<b>Bill To,</b>", section_title_style)],
        [Paragraph(f"M/s. {user.name}", normal_style)],
        [Paragraph(f"Email: {user.company_email}", normal_style)]
    ]
    
    invoice_details_content = [
        [Paragraph(f"<b>Invoice No:</b> {token_purchase.invoice_number}", normal_style)],
        [Paragraph(f"<b>Date:</b> {token_purchase.invoice_date.strftime('%d/%m/%Y')}", normal_style)],
        [Paragraph(f"<b>Order ID:</b> {token_purchase.razorpay_order_id}", normal_style)],
        [Paragraph(f"<b>Payment ID:</b> {token_purchase.razorpay_payment_id}", normal_style)]
    ]
    
    bill_invoice_data = [[
        Table(bill_to_content),
        Table(invoice_details_content)
    ]]
    
    bill_invoice_table = Table(bill_invoice_data, colWidths=[doc.width*0.6, doc.width*0.4])
    elements.append(bill_invoice_table)
    elements.append(Spacer(1, 15))
    
    # Service Details Table
    headers = ['Sl No', 'Description of Service', 'SAC/HSN', 'Qty', 'Rate', 'Amount (Rs)']
    
    table_data = []
    table_data.append(headers)
    
    # Token purchase row
    table_data.append([
        '1.',
        f'Additional Usage Tokens ({token_purchase.token_count} tokens)',
        '998314',
        str(token_purchase.token_count),
        '2.00',
        f'{token_purchase.base_amount:.2f}'
    ])
    
    # Tax rows
    cgst_amount = token_purchase.gst_amount / 2
    sgst_amount = token_purchase.gst_amount / 2
    
    table_data.append(['', '', '', '', 'Subtotal', f'{token_purchase.base_amount:.2f}'])
    table_data.append(['', '', '', '', 'CGST @ 9%', f'{cgst_amount:.2f}'])
    table_data.append(['', '', '', '', 'SGST @ 9%', f'{sgst_amount:.2f}'])
    
    col_widths = [doc.width*0.08, doc.width*0.40, doc.width*0.12, doc.width*0.08, doc.width*0.16, doc.width*0.16]
    service_table = Table(table_data, colWidths=col_widths)
    
    service_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), brand_color),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (0, 1), (0, -1), 'CENTER'),
        ('ALIGN', (5, 1), (5, -1), 'RIGHT'),
        ('FONTNAME', (4, 2), (5, -1), 'Helvetica-Bold'),
    ]))
    
    elements.append(service_table)
    
    # Total
    total_table_data = [
        ['Total Invoice Value', f'₹{token_purchase.total_amount:.2f}']
    ]
    
    total_table = Table(total_table_data, colWidths=[doc.width*0.8, doc.width*0.2])
    total_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), secondary_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), brand_color),
        ('ALIGN', (0, 0), (0, 0), 'RIGHT'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(total_table)
    
    # Amount in words
    amount_words = num2words(int(token_purchase.total_amount), lang='en_IN').title()
    words_data = [[f'Rupees in words: {amount_words} Rupees Only']]
    words_table = Table(words_data, colWidths=[doc.width])
    words_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(words_table)
    elements.append(Spacer(1, 15))
    
    # Signature area
    signature_data = [
        ['', 'For Fourth Dimension Media Solutions (P) Ltd'],
        ['', ''],
        ['', 'Authorised Signatory']
    ]
    
    signature_table = Table(signature_data, colWidths=[doc.width*0.6, doc.width*0.4])
    signature_table.setStyle(TableStyle([
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (1, 0), (1, -1), 9),
    ]))
    elements.append(signature_table)
    elements.append(Spacer(1, 15))
    
    # Terms & Conditions and Bank Details
    terms_conditions = [
        [Paragraph("<b>Terms & Condition</b>", section_title_style)],
        [Paragraph("• All disputes are subject to Chennai Jurisdiction only", normal_style)],
        [Paragraph('• Kindly Make all payments favoring "Fourth Dimension Media Solutions Pvt Ltd"', normal_style)],
        [Paragraph("• Payment terms: Immediate", normal_style)],
        [Paragraph("• Bank Name: City Union Bank., Tambaram West, Chennai -45", normal_style)],
        [Paragraph("  Account No: 512120020019966", normal_style)],
        [Paragraph("  Account Type: OD", normal_style)],
        [Paragraph("  IFSC Code: CIUB0000117", normal_style)]
    ]
    
    terms_table = Table(terms_conditions, colWidths=[doc.width])
    terms_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ('FONTSIZE', (0, 1), (-1, -1), 7),  # Smaller font for terms
    ]))
    elements.append(terms_table)
    
    # Build PDF
    doc.build(elements)
    
    # Reset buffer position
    buffer.seek(0)
    
    return buffer

# 6. Route to download token invoice
@app.route('/download_token_invoice/<int:token_purchase_id>')
@login_required
@csrf.exempt
def download_token_invoice(token_purchase_id):
    user_id = session.get('user_id')
    
    # Get token purchase
    token_purchase = TokenPurchase.query.filter_by(
        id=token_purchase_id,
        user_id=user_id,
        status='completed'
    ).first_or_404()
    
    if not token_purchase.invoice_number:
        flash('Invoice not available for this token purchase.', 'warning')
        return redirect(url_for('user_subscriptions'))
    
    # Generate invoice PDF
    pdf_buffer = generate_token_invoice_pdf(token_purchase)
    
    return send_file(
        pdf_buffer,
        download_name=f"token_invoice_{token_purchase.invoice_number}.pdf",
        as_attachment=True,
        mimetype='application/pdf'
    )
    
# Replace the existing get_user_token_summary function in app.py

def get_user_token_summary(user_id):
    """Get comprehensive token usage summary for a user"""
    try:
        # Get active subscription
        active_subscription = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date > datetime.now(UTC))
            .filter(SubscribedUser._is_active == True)
            .first()
        )
        
        if not active_subscription:
            return None
        
        # Check if daily limit is reached
        daily_limit_reached = active_subscription.current_usage >= active_subscription.subscription.usage_per_day
        
        # ✅ Changed: Get ALL user's token records that haven't expired (not just current subscription)
        user_tokens = (
            UserToken.query
            .filter(UserToken.user_id == user_id)
            .filter(UserToken.expires_at > datetime.now(UTC))  # Only check if not expired
            .all()
        )
        
        # Calculate token totals
        total_tokens_purchased = sum(token.tokens_purchased for token in user_tokens)
        total_tokens_used = sum(token.tokens_used for token in user_tokens)
        purchased_tokens_available = sum(token.tokens_remaining for token in user_tokens)
        
        return {
            'daily_limit_reached': daily_limit_reached,
            'total_tokens_purchased': total_tokens_purchased,
            'total_tokens_used': total_tokens_used,
            'purchased_tokens_available': purchased_tokens_available,
            'active_subscription': active_subscription
        }
        
    except Exception as e:
        app.logger.error(f"Error getting token summary: {str(e)}")
        return None
def use_additional_token(user_id):
    """Use one additional token if available"""
    try:
        # Get available tokens (oldest first)
        available_tokens = (
            UserToken.query
            .filter(UserToken.user_id == user_id)
            .filter(UserToken.tokens_remaining > 0)
            .filter(UserToken.expires_at > datetime.now(UTC))
            .order_by(UserToken.created_at.asc())
            .all()
        )
        
        if not available_tokens:
            return False
        
        # Use token from oldest purchase first
        token_record = available_tokens[0]
        token_record.tokens_used += 1
        token_record.tokens_remaining -= 1
        
        db.session.commit()
        return True
        
    except Exception as e:
        app.logger.error(f"Error using additional token: {str(e)}")
        db.session.rollback()
        return False

@app.route('/debug/token_status')
@login_required
def debug_token_status():
    """Debug route to check current token status"""
    if not app.debug:
        return "Debug mode only", 404
    
    user_id = session.get('user_id')
    
    try:
        # Get token summary
        usage_summary = get_user_token_summary(user_id)
        
        # Get all token purchases
        token_purchases = TokenPurchase.query.filter_by(user_id=user_id).all()
        
        # Get all user tokens
        user_tokens = UserToken.query.filter_by(user_id=user_id).all()
        
        # Get active subscription
        active_subscription = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date > datetime.now(UTC))
            .filter(SubscribedUser._is_active == True)
            .first()
        )
        
        return jsonify({
            'user_id': user_id,
            'usage_summary': {
                'daily_limit_reached': usage_summary.get('daily_limit_reached') if usage_summary else None,
                'total_tokens_purchased': usage_summary.get('total_tokens_purchased') if usage_summary else 0,
                'total_tokens_used': usage_summary.get('total_tokens_used') if usage_summary else 0,
                'purchased_tokens_available': usage_summary.get('purchased_tokens_available') if usage_summary else 0,
            } if usage_summary else None,
            'token_purchases': [
                {
                    'id': tp.id,
                    'token_count': tp.token_count,
                    'status': tp.status,
                    'created_at': tp.created_at.isoformat()
                } for tp in token_purchases
            ],
            'user_tokens': [
                {
                    'id': ut.id,
                    'tokens_purchased': ut.tokens_purchased,
                    'tokens_used': ut.tokens_used,
                    'tokens_remaining': ut.tokens_remaining,
                    'expires_at': ut.expires_at.isoformat()
                } for ut in user_tokens
            ],
            'active_subscription': {
                'id': active_subscription.id,
                'current_usage': active_subscription.current_usage,
                'daily_limit': active_subscription.subscription.usage_per_day,
                'end_date': active_subscription.end_date.isoformat()
            } if active_subscription else None
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})
    
# Add this temporary route to check database tables
@app.route('/debug/check_tables')
@login_required
def debug_check_tables():
    """Debug route to check if token tables exist"""
    if not app.debug:
        return "Debug mode only", 404
    
    try:
        # Check if tables exist
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        token_tables = {
            'token_purchases': 'token_purchases' in tables,
            'user_tokens': 'user_tokens' in tables
        }
        
        # Check if there are any token purchases
        token_purchases_count = 0
        user_tokens_count = 0
        
        if token_tables['token_purchases']:
            token_purchases_count = TokenPurchase.query.count()
        
        if token_tables['user_tokens']:
            user_tokens_count = UserToken.query.count()
        
        return jsonify({
            'tables_exist': token_tables,
            'token_purchases_count': token_purchases_count,
            'user_tokens_count': user_tokens_count,
            'user_id': session.get('user_id')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})
    
@app.route('/help')
def help_page():
    """Help page with comprehensive documentation"""
    return render_template('help.html')
# Add this route to your app.py for cron job endpoint
@app.route('/cron/handle-expired-subscriptions')
def cron_handle_expired_subscriptions():
    """
    Cron job endpoint to handle expired subscriptions and pause tokens
    This should be called daily by your server's cron job
    """
    try:
        # Optional: Add authentication for cron job
        cron_secret = request.headers.get('X-Cron-Secret')
        expected_secret = app.config.get('CRON_SECRET', 'your-secret-key')
        
        if cron_secret != expected_secret:
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Process expired subscriptions
        subscriptions_processed, tokens_paused = handle_expired_subscriptions()
        
        # Also run auto-renewal process
        process_auto_renewals()
        
        result = {
            'success': True,
            'subscriptions_processed': subscriptions_processed,
            'tokens_paused': tokens_paused,
            'timestamp': datetime.now(UTC).isoformat()
        }
        
        app.logger.info(f"Cron job completed: {result}")
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Cron job failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now(UTC).isoformat()
        }), 500
def migrate_existing_tokens():
    """
    One-time migration to extend expiration of existing tokens
    Run this once after deploying the changes
    """
    try:
        with app.app_context():
            # Find all tokens that expired but still have remaining balance
            expired_tokens = UserToken.query.filter(
                UserToken.expires_at <= datetime.now(UTC),
                UserToken.tokens_remaining > 0
            ).all()
            
            updated_count = 0
            for token in expired_tokens:
                # Extend expiration to 1 year from now
                token.expires_at = datetime.now(UTC) + timedelta(days=365)
                updated_count += 1
            
            if updated_count > 0:
                db.session.commit()
                app.logger.info(f"Extended expiration for {updated_count} token records")
                print(f"✅ Extended expiration for {updated_count} token records")
            else:
                print("ℹ️  No expired tokens found to update")
                
            return updated_count
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in token migration: {str(e)}")
        print(f"❌ Error in token migration: {str(e)}")
        return -1

# Add this route temporarily to run the migration
@app.route('/admin/migrate-tokens')
@admin_required
def migrate_tokens_route():
    """Temporary route to migrate existing tokens"""
    updated_count = migrate_existing_tokens()
    if updated_count >= 0:
        flash(f'Successfully extended expiration for {updated_count} token records', 'success')
    else:
        flash('Error during token migration', 'danger')
    return redirect(url_for('admin_dashboard'))
# Initialize the app AFTER all functions are defined
application = create_app()

# For WSGI deployment
app = application

# Only run directly if in development
if __name__ == "__main__":
    if os.environ.get('FLASK_ENV') != 'production':
        application.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Use a WSGI server like Gunicorn for production")