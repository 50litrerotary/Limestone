from flask import Flask, render_template, request
from livereload import Server

app = Flask(__name__)

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # handle login logic here (e.g., authentication)
        pass
    return render_template('login.html')

@app.route('/bookshelf')
def bookshelf():
    # You can pass book data later if needed
    return render_template('bookshelf.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # handle registration logic here
        pass
    return render_template('register.html')

if __name__ == '__main__':
    server = Server(app.wsgi_app)
    server.serve(port=5001, debug=True)
