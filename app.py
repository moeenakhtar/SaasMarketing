from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'replace-with-a-secure-secret-key'

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# In-memory user store for demonstration purposes
# Replace this with a database in production
users = {
    'admin': generate_password_hash('password'),
    'user': generate_password_hash('secret')
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

    def __repr__(self):
        return f'<User {self.id}>'

@login_manager.user_loader
def load_user(user_id):
    # Return a User object if the user exists in our store
    if user_id in users:
        return User(user_id)
    return None

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Validate credentials
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
