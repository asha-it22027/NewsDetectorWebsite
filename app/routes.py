from flask import render_template, flash, redirect, url_for, request
from app import app, db
from app.models import User, Verification, Source
from flask_login import current_user, login_user, logout_user, login_required
from urllib.parse import urlsplit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
import random
import json
import wikipedia
from sqlalchemy.exc import IntegrityError

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

class VerifyNewsForm(FlaskForm):
    news_text = StringField('News Text', validators=[DataRequired()])
    submit = SubmitField('Verify')

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

import wikipedia
from sqlalchemy.exc import IntegrityError

# ... (rest of the imports and forms)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = VerifyNewsForm()
    result = None

    RELIABILITY_MAPPING = {
        'government': 5, 'academic': 5, 'factcheck': 5,
        'news': 4, 'regional': 3, 'social': 1
    }
    RELIABILITY_BADGE_TEXT = {5: 'Very High', 4: 'High', 3: 'Medium', 1: 'Low'}

    if form.validate_on_submit():
        news_text = form.news_text.data
        explanation_points = []
        
        # --- Wikipedia Integration ---
        # Ensure Wikipedia source exists and is used for verification
        selected_source = Source.query.filter_by(title='Wikipedia').first()
        if not selected_source:
            selected_source = Source(
                url="https://www.wikipedia.org",
                source_type="academic",
                title="Wikipedia",
                author="Community"
            )
            db.session.add(selected_source)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                selected_source = Source.query.filter_by(title='Wikipedia').first()

        truth_score = 50  # Start with a neutral score
        wikipedia_page_url = None
        
        try:
            # Search Wikipedia for the news text
            search_results = wikipedia.search(news_text)
            if not search_results:
                raise wikipedia.exceptions.PageError(pageid=news_text)

            # Get the first result page
            page = wikipedia.page(search_results[0], auto_suggest=False)
            summary = wikipedia.summary(search_results[0], sentences=2)
            
            truth_score += 25  # Boost score for finding a relevant article
            explanation_points.append(f"Claim supported by Wikipedia: '{page.title}'.")
            explanation_points.append(f"Summary: {summary}")
            wikipedia_page_url = page.url

        except (wikipedia.exceptions.PageError, wikipedia.exceptions.DisambiguationError):
            truth_score -= 25  # Penalize score for no clear article
            explanation_points.append("No specific supporting article found on Wikipedia for this claim.")

        derived_reliability_score = RELIABILITY_MAPPING.get(selected_source.source_type.lower(), 1)
        reliability_badge_text = RELIABILITY_BADGE_TEXT.get(derived_reliability_score, 'Unknown')

        if derived_reliability_score == 5:
            truth_score += 15
            explanation_points.insert(0, f"Verification conducted using a very high reliability source ({selected_source.title}).")
        
        truth_score = max(0, min(100, truth_score))
        false_score = 100 - truth_score

        classification = "Partially True"
        if truth_score >= 80:
            classification = "Mostly True"
        elif truth_score <= 30:
            classification = "False"
        
        explanation = " ".join(explanation_points)

        result = {
            "truth_score": truth_score,
            "false_score": false_score,
            "classification": classification,
            "explanation": explanation,
            "source_title": selected_source.title,
            "source_url": wikipedia_page_url or selected_source.url,
            "source_type": selected_source.source_type,
            "reliability_badge": reliability_badge_text,
            "wikipedia_url": wikipedia_page_url,
        }
        
        verification = Verification(
            content=news_text, truth_score=truth_score,
            false_score=false_score, classification=classification,
            explanation=explanation, source_id=selected_source.id,
            author=current_user
        )
        db.session.add(verification)
        db.session.commit()
        flash('Verification saved to your history.', 'success')

    verifications = current_user.verifications.order_by(Verification.timestamp.desc()).all()
    for v in verifications:
        if v.source_id:
            v.source_details = Source.query.get(v.source_id)
            v.reliability_badge = RELIABILITY_BADGE_TEXT.get(RELIABILITY_MAPPING.get(v.source_details.source_type.lower(), 1), 'Unknown')
        else:
            v.source_details = None
            v.reliability_badge = 'N/A'
            
    chart_data = {
        'labels': ['False', 'Partially True', 'Mostly True'],
        'counts': [0, 0, 0]
    }
    for v in verifications:
        if v.classification == 'False': chart_data['counts'][0] += 1
        elif v.classification == 'Partially True': chart_data['counts'][1] += 1
        else: chart_data['counts'][2] += 1
            
    return render_template('dashboard.html', title='Dashboard', form=form, result=result, verifications=verifications, chart_data=chart_data)

@app.route('/history')
@login_required
def history():
    verifications = current_user.verifications.order_by(Verification.timestamp.desc()).all()
    return render_template('history.html', title='Verification History', verifications=verifications)

@app.route('/delete_verification/<int:verification_id>', methods=['POST'])
@login_required
def delete_verification(verification_id):
    verification = Verification.query.get_or_404(verification_id)
    if verification.author != current_user:
        flash('You are not authorized to delete this item.', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(verification)
    db.session.commit()
    flash('Verification history item deleted.', 'success')
    return redirect(url_for('dashboard'))