from flask import Flask,render_template,redirect,request,sessions,url_for,logging,flash,session
from passlib.hash import sha256_crypt
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker

engine=create_engine('mssql+pyodbc://@localhost/quelin?driver=SQL+Server+Native+Client+11.0')

db=scoped_session(sessionmaker(bind=engine))

app=Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"




app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form.get("name")
        email=request.form.get("email")
        password=request.form.get("password")
        confirm_password=request.form.get("confirm_password")
        secure_password=sha256_crypt.encrypt(str(password))

        if password==confirm_password:
            db.execute("INSERT INTO users(name,email,password) VALUES(:name,:email,:password)",
                        {"name":name,"email":email,"password":secure_password})
            db.commit()
            flash("registration succesfull","success")
            return redirect(url_for('login'))
        else:
            flash("password did not match","danger")
            return render_template("register.html")
    
    else:
        return render_template("register.html")


@app.route("/login",methods=["GET","POST"])
def login():
    session.clear()

    if request.method=="POST":
        email=request.form.get("email")
        password=request.form.get("password")

        email_data=db.execute("SELECT email FROM users WHERE email=:email",{"email":email}).fetchone()
        password_data=db.execute("SELECT password FROM users WHERE email=:email",{"email":email}).fetchone()
        

        if email_data is None:
            flash("no email found","danger")
            return render_template("login.html")
        else:
            for pas in password_data:
                if sha256_crypt.verify(password,pas):
                    id=db.execute("SELECT id FROM users WHERE email=:email",{"email":email}).fetchone()
                    if id[0] not in session:
                        session["user_id"]=id[0]
                    flash("Login successful","success")
                    return render_template("index.html",user_id=session["user_id"])
                else:
                    flash("incorrect password","danger")
                    return render_template("login.html")

    else:     
        return render_template("login.html")

@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("logged out succesfully","success")
    return redirect("/")

if __name__=="__main__":
    app.secret_key="951753123456987"
    app.run()