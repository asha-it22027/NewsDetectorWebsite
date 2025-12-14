from flask import render_template, flash, redirect, url_for, request
from app import app, db
from app.models import User, Verification
from flask_login import current_user, login_user, logout_user, login_required
from urllib.parse import urlsplit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
import random
import json

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

# Routes
@app.route('/')
@app.route('/index')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('dashboard')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    result = None
    if request.method == 'POST':
        news_text = request.form.get('news_text')
        if news_text:
            # "Intelligent" mock verification logic
            lower_text = news_text.lower()
            
            # --- Source Layer A: Official & Trusted Sources ---
            trusted_sources_match = []
            if 'nasa' in lower_text or 'space' in lower_text:
                trusted_sources_match.append('NASA research')
            if 'who' in lower_text or 'health' in lower_text:
                trusted_sources_match.append('WHO guidelines')
            if 'reuters' in lower_text or 'bbc' in lower_text:
                trusted_sources_match.append('Reputable news agencies')

            # --- Source Layer B: Fact-Checking Websites ---
            debunked_by_factcheck = False
            if any(k in lower_text for k in ['hoax', 'fake news', 'debunked']):
                debunked_by_factcheck = True

            # --- Source Layer C: AI / NLP Analysis (Mock) ---
            sensational_words_detected = any(k in lower_text for k in ['shocking', 'never before', 'scientists shocked', 'unbelievable'])
            anonymous_source_detected = 'anonymous source' in lower_text or 'unnamed source' in lower_text
            evidence_mentioned = any(k in lower_text for k in ['data shows', 'studies prove', 'evidence suggests'])
            date_mismatch = '2019' in lower_text and 'pandemic' in lower_text and random.random() < 0.3 # Simulate some mismatch

            explanation_points = []
            mock_sources = []
            truth_score = random.randint(50, 70) # Base probability

            if trusted_sources_match:
                truth_score += len(trusted_sources_match) * 10
                explanation_points.append(f"Information aligns with {', '.join(trusted_sources_match)}.")
                mock_sources.extend([
                    "https://www.nasa.gov/webb",
                    "https://www.who.int/",
                    "https://www.bbc.com/news/"
                ])

            if debunked_by_factcheck:
                truth_score -= 40
                explanation_points.append("Similar claims have been debunked by fact-checking websites like Snopes or PolitiFact.")
                mock_sources.extend([
                    "https://www.snopes.com/",
                    "https://www.politifact.com/"
                ])
            
            if sensational_words_detected:
                truth_score -= 15
                explanation_points.append("Sensational language detected, often used in misleading content.")
            if anonymous_source_detected:
                truth_score -= 20
                explanation_points.append("Reliance on anonymous sources raises credibility concerns.")
            if evidence_mentioned:
                truth_score += 10
                explanation_points.append("Mention of data/evidence, suggesting a basis for claims.")
            if date_mismatch:
                truth_score -= 10
                explanation_points.append("Potential date mismatch or outdated information detected.")

            truth_score = max(0, min(100, truth_score)) # Clamp score between 0 and 100
            false_score = 100 - truth_score

            classification = "Partially True"
            if truth_score >= 80:
                classification = "Mostly True"
            elif truth_score <= 30:
                classification = "False"
            
            explanation = " ".join(explanation_points) if explanation_points else "No specific issues or alignments found during analysis."
            
            # Format sources as JSON string
            source_json = json.dumps(list(set(mock_sources))) if mock_sources else None

            result = {
                "truth_score": truth_score,
                "false_score": false_score,
                "classification": classification,
                "explanation": explanation,
                "source": source_json # Store as JSON string
            }
            
            verification = Verification(content=news_text, truth_score=truth_score,
                                        false_score=false_score, classification=classification,
                                        explanation=explanation, source=source_json,
                                        author=current_user)
            db.session.add(verification)
            db.session.commit()
            flash('Verification saved to your history.')

    verifications = current_user.verifications.order_by(Verification.timestamp.desc()).all()

    # Prepare data for chart
    chart_data = {
        'labels': ['False', 'Partially True', 'Mostly True'],
        'counts': [0, 0, 0]
    }
    for v in verifications:
        if v.classification == 'False':
            chart_data['counts'][0] += 1
        elif v.classification == 'Partially True':
            chart_data['counts'][1] += 1
        elif v.classification == 'Mostly True':
            chart_data['counts'][2] += 1
            
    return render_template('dashboard.html', title='Dashboard', result=result, verifications=verifications, chart_data=chart_data)

@app.route('/history')
@login_required
def history():
    verifications = current_user.verifications.order_by(Verification.timestamp.desc()).all()
    return render_template('history.html', title='Verification History', verifications=verifications)