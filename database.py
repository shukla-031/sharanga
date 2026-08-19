@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not cursor.fetchone():
                print("❌ Users table not found! Initializing database...")
                init_db()
                conn = get_db_connection()
                cursor = conn.cursor()
            
            user = cursor.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            else:
                return render_template('login.html', error='❌ Invalid username or password')
        except Exception as e:
            print(f"❌ Login error: {e}")
            print(traceback.format_exc())
            return render_template('login.html', error='❌ Database error. Please try again.')
    
    return render_template('login.html')