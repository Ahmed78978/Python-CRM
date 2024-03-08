
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from flask_apscheduler import APScheduler
# Other imports remain the same...
from apscheduler.schedulers.background import BackgroundScheduler


# Create a scheduler instance and set the timezone to 'Asia/Karachi' for Pakistani time

app = Flask(__name__)
schedulers = BackgroundScheduler(timezone='US/Eastern')

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()
# Replace this with your MySQL database details
username = 'mysql'
password = 'A7TZ65MmpEm/DuCqhEhTTkphLb7C7WJEKrg9s7UgQzg='
hostname = 'mysql-gaaq'  # Use the actual hostname from the image you provided
port = '3306'  # Use the actual port if different
database = 'mysql'

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{username}:{password}@{hostname}:{port}/{database}'





app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from datetime import date
import imaplib
import email
import re
from email.header import decode_header
host = "imap.gmail.com"
user='paycarrent88@gmail.com'
passa='yraqquqhosjuhblh'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate():
    """Authenticate and authorize the user."""
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return creds
previous_email_ids = set()
def fetch_new_emails():
    """Fetch and print new unread emails."""
    creds = authenticate()
    gmail = Gmail(creds)
    global previous_email_ids

    new_emails = gmail.get_unread_inbox()
    for email in new_emails:
            if email.id not in previous_email_ids:
                previous_email_ids.add(email.id)
                return email.plain


def read_and_skip_flagged_emails(count=3, contain_body=True, mail_server='imap.gmail.com', user=user,passa=passa):
    # Connect to the server
    mail = imaplib.IMAP4_SSL(mail_server)
    mail.login(user, passa)

    # Select the inbox
    res, messages = mail.select('INBOX')

    # Calculate the total number of emails
    messages = int(messages[0])

    # Iterate over the specified number of emails
    for i in range(messages, messages - count, -1):
        # Fetch the email flags to see if it has been read/seen
        res, flags = mail.fetch(str(i), "(FLAGS)")
        if '\\Seen' in str(flags):
            print(f"Skipping email {i} as it has been marked as read.")
            continue  # Skip this email as it's already been read
        else:
            # Fetch the email by its ID using the RFC822 protocol
            res, msg = mail.fetch(str(i), "(RFC822)")
            for response in msg:
                if isinstance(response, tuple):
                    # Parse the bytes email into a message object
                    msg = email.message_from_bytes(response[1])

                    sender = msg["From"]

                    # Extract the email subject
                    subject = msg["Subject"]
                    print(subject)

                    # Extract and decode the email body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            charset = part.get_content_charset()
                            if content_type in ["text/plain", "text/html"]:
                                body = part.get_payload(decode=True).decode(charset)
                                break
                    else:
                        charset = msg.get_content_charset()
                        body = msg.get_payload(decode=True).decode(charset)

                    # Optionally print the email content
                   # print("BODY: ",body)

                    if contain_body:
                        if not body:
                            return body
                        else:
                         return body


                    # Mark the email as read/seen
                    mail.store(str(i), '+FLAGS', '\\Seen')


    # Close the mailbox
    mail.close()

    # Log out from the server
    mail.logout()
previous_email_content = None

# Define the job to update customer balances daily
from pytz import timezone
from datetime import datetime

#eastern = timezone('US/Eastern')

#@scheduler.task('cron', id='daily_balance_update', hour='0', minute='0', second='0', misfire_grace_time=900)


# Adjust the scheduled task decorator for 3:35 AM PKT
@schedulers.scheduled_job('cron', id='daily_balance_update', hour='0', minute='0', second='0', misfire_grace_time=900)
def daily_balance_update():
    with app.app_context():
        customers = Customer.query.all()  # Fetch all customer records
        for customer in customers:
            customer.current_balance += customer.daily_rate  # Increase balance by daily rate
            # Optionally, you can create a transaction record for each update
            new_transaction = Transaction(amount=customer.daily_rate, description='Daily rate addition', customer_id=customer.id)
            db.session.add(new_transaction)
        db.session.commit()  # Commit changes to the database
        print("Updated customer balances based on daily rates.")


# Define the job to read emails and update database


def update_database():

  with app.app_context():

    new_email_content = fetch_new_emails()

    print("New Email ", new_email_content)
    if new_email_content is not None:

     try:
        try:
         new_email_content_str = new_email_content.decode('utf-8')
        except:
            new_email_content_str=new_email_content
        payment_from_name = re.search(r"Payment from \$(\w+)", new_email_content_str)

        if payment_from_name:
            payment_from_name = payment_from_name.group(1)
            print("paymentname ",payment_from_name)

        # Extract amount
        amount = re.search(r"\$([0-9,.]+)", new_email_content)
        if amount:
            amount = amount.group(1)
            print("amount: ",amount)

            # Fetch customer from database and update balance
            customer = User.query.filter_by(cashapp_username=payment_from_name).first()
            if customer:
                customer_email = customer.username
                customer=Customer.query.filter_by(email=customer_email).first()
                preba=customer.current_balance
                customer.current_balance -= float(amount)
                print(customer.name)

                transaction_description = f"Balance updated by CashApp. Previous balance: {preba}, New balance: {customer.current_balance}"
                new_transaction = Transaction(amount=amount, description=transaction_description,
                                              customer_id=customer.id)
                db.session.add(new_transaction)
                db.session.commit()
     except:



        pass
    # Update previous_email_content with the new email content
    previous_email_content = new_email_content

schedulers.add_job(func=update_database, trigger="interval", seconds=120)
schedulers.start()
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    opening_balance = db.Column(db.Float, default=0)
    current_balance = db.Column(db.Float, default=0)
    daily_rate = db.Column(db.Float, default=0)  # Daily increment to the balance
    transactions = db.relationship('Transaction', backref='customer', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=date.today)
    amount = db.Column(db.Float, nullable=False)  # Use negative values for payments
    description = db.Column(db.String(255))
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    cashapp_username = db.Column(db.String(50),  nullable=False)



@app.route('/admin/customer', methods=['GET', 'POST'])
def admin_customer():
    if request.method == 'POST':
        # Extract data from form
        name = request.form['name']
        email = request.form['email']
        opening_balance = request.form.get('opening_balance', 0, type=float)
        daily_rate = request.form.get('daily_rate', 0, type=float)

        # Create or update customer
        customer = Customer.query.filter_by(email=email).first()

        if customer:
            customer.name = name
            customer.opening_balance = opening_balance
            customer.current_balance = opening_balance
            customer.daily_rate = daily_rate
            transaction_description = f"Thank You {name} for renting with us, your openning Balance is {opening_balance} with daily rate of {daily_rate}"
            new_transaction = Transaction(amount=amount, description=transaction_description,
                                          customer_id=customer.id)
            db.session.add(new_transaction)
        else:
            customer = Customer(name=name, email=email, opening_balance=opening_balance,
                                current_balance=opening_balance, daily_rate=daily_rate)
            db.session.add(customer)
            customer = Customer.query.filter_by(email=email).first()
            transaction_description = f"Thank You {customer.name} for renting with us, your openning Balance is {customer.opening_balance} with daily rate of {customer.daily_rate}"
            new_transaction = Transaction(amount=amount, description=transaction_description,
                                          customer_id=customer.id)
            db.session.add(new_transaction)
        db.session.commit()

        return redirect(url_for('admin_dashboard'))
    return render_template('admin_customer.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
   # if not current_user.is_admin:  # Assuming `is_admin` is a boolean attribute of User model
    #    return "Access denied", 403
    customers = Customer.query.all()
    return render_template('admin_dashboard.html', customers=customers)
@app.route('/admin/customer/<int:customer_id>', methods=['GET', 'POST'], endpoint='admin_edit_customer')
@login_required
def admin_customer(customer_id):
    if not current_user.is_admin:
        return "Access denied", 403

    customer = Customer.query.get_or_404(customer_id)

    if request.method == 'POST':
        customer.opening_balance = request.form.get('opening_balance', type=float)
        customer.daily_rate = request.form.get('daily_rate', type=float)
        db.session.commit()
        flash('Customer details updated successfully.')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_customer.html', customer=customer)


@app.route('/admin/update_balance/<int:customer_id>', methods=['POST'])
@login_required
def update_balance(customer_id):
    if not current_user.is_admin:
        return "Access denied", 403

    customer = Customer.query.get_or_404(customer_id)
    payment_amount = float(request.form['payment'])
    previous_balance = customer.current_balance
    customer.current_balance -= payment_amount

    # Creating a transaction log
    transaction_description = f"Balance updated by {current_user.username}. Previous balance: {previous_balance}, New balance: {customer.current_balance}"
    new_transaction = Transaction(amount=payment_amount, description=transaction_description, customer_id=customer_id)
    db.session.add(new_transaction)

    db.session.commit()
    flash('Customer balance updated and transaction logged.', 'success')
    return redirect(url_for('admin_dashboard'))





@app.route('/')
@login_required
def index():
    if current_user.is_admin:  # If the user is an admin, show the admin dashboard
        return redirect(url_for('admin_dashboard'))
    else:  # If the user is not an admin, show the customer dashboard
        return redirect(url_for('customer_dashboard'))
@app.route('/dashboard')
@login_required
def user_dashboard():
    # Assuming the username is used as the email for the customer.
    customer_email = current_user.username  # If username is the email
    customer = Customer.query.filter_by(email=customer_email).first_or_404()
    transactions = Transaction.query.filter_by(customer_id=customer.id).order_by(Transaction.date.desc()).all()
    return render_template('user_dashboard.html', customer=customer, transactions=transactions)
@login_manager.user_loader
def load_user(id):
    user = None
    for x in range(6):
        try:
            user = db.session.get(User, int(id))
            break
        except:
            pass
    return user




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(is_admin=1).first()
        print(user)
        user = User.query.filter_by(username=username).first()

        if user and user.password== password:

            login_user(user)
            return redirect(url_for('index'))
        #return 'Invalid username or password'
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        username=username.lower()
        password = request.form['password']
        #hashed_password = generate_password_hash(password)


        # Check if 'is_admin' checkbox was checked in the registration form
        is_admin = request.form.get('role') == 'admin'
        cashapp_username = request.form.get('cashapp')
        if not cashapp_username:
            flash('CashApp username is required')
            #return('CashApp username is required')


        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print('exist')
            flash('User already exists')
        else:
            user = User.query.filter_by(cashapp_username=cashapp_username).first()
            if user:
                flash('CashAPP already exists')
            else:
                new_user = User(username=username, password=password, is_admin=is_admin,
                                cashapp_username=cashapp_username)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful')
                customer_email = username
                customer = Customer.query.filter_by(email=customer_email).first()
                if not customer:
                    # If no customer record exists, create a new one with default values
                    customer = Customer(email=customer_email, name=username, opening_balance=0,
                                        current_balance=0,
                                        daily_rate=0)
                    db.session.add(customer)
                    db.session.commit()
                return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    customer_email = current_user.username  # Assuming username is the email.

    # Attempt to fetch the customer; if not found, create a new one
    customer = Customer.query.filter_by(email=customer_email).first()
    if not customer:
        # If no customer record exists, create a new one with default values
        customer = Customer(email=customer_email, name=current_user.username, opening_balance=0, current_balance=0,
                            daily_rate=0)
        db.session.add(customer)
        db.session.commit()

    # Now customer is guaranteed to exist, so fetch transactions
    transactions = Transaction.query.filter_by(customer_id=customer.id).order_by(Transaction.date.desc()).all()

    return render_template('customer_dashboard.html', customer=customer, transactions=transactions)


@app.route('/admin/add_customer', methods=['GET', 'POST'])
@login_required
def add_customer():
    if not current_user.is_admin:
        return "Access denied", 403

    if request.method == 'POST':
        # Extract data from form
        customer_id = request.form.get('customer')
        opening_balance = request.form.get('opening_balance', type=float)
        daily_rate = request.form.get('daily_rate', type=float)

        # Find the customer by ID
        customer = Customer.query.get_or_404(customer_id)

        # Update customer's opening balance and daily rate
        customer.opening_balance = opening_balance
        customer.current_balance = opening_balance  # Assuming you want to reset the current balance as well
        customer.daily_rate = daily_rate
        transaction_description = f"Welcome, {customer.name}! Your rental journey begins with an opening balance of {customer.opening_balance} and a daily rate of {customer.daily_rate}. Happy driving!"
        new_transaction = Transaction(amount=customer.opening_balance, description=transaction_description,
                                      customer_id=customer_id)
        db.session.add(new_transaction)




        # Save changes to the database
        db.session.commit()

        flash('Customer record has been updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    # Fetch all customers to display in the dropdown
    customers = Customer.query.all()
    return render_template('add_customer.html', customers=customers)


if __name__ == '__main__':

    with app.app_context():
        db.create_all()
    app.run(debug=True)

