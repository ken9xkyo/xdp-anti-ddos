from flask import Flask, render_template, request, redirect, url_for, flash
import xdp_wrapper
import os
import secrets

app = Flask(__name__)
# FIX: Use environment variable for secret key, generate secure fallback
app.secret_key = os.environ.get('XDP_SECRET_KEY') or secrets.token_hex(32)

@app.route('/')
def index():
    stats = xdp_wrapper.get_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/whitelist', methods=['GET', 'POST'])
def whitelist():
    if request.method == 'POST':
        action = request.form.get('action')
        ip = request.form.get('ip')
        
        if action == 'add' and ip:
            err = xdp_wrapper.add_whitelist(ip)
            if err:
                flash(f'Error adding IP: {err}', 'error')
            else:
                flash(f'Added {ip} to whitelist', 'success')
        elif action == 'remove' and ip:
            err = xdp_wrapper.remove_whitelist(ip)
            if err:
                flash(f'Error removing IP: {err}', 'error')
            else:
                flash(f'Removed {ip} from whitelist', 'success')
        
        return redirect(url_for('whitelist'))
        
    ips = xdp_wrapper.get_whitelist()
    return render_template('whitelist.html', ips=ips)

@app.route('/ports', methods=['GET', 'POST'])
def ports():
    if request.method == 'POST':
        action = request.form.get('action')
        port = request.form.get('port')
        
        if action == 'add' and port:
            err = xdp_wrapper.add_port(port)
            if err:
                flash(f'Error adding port: {err}', 'error')
            else:
                flash(f'Added port {port} to block list', 'success')
        elif action == 'remove' and port:
            err = xdp_wrapper.remove_port(port)
            if err:
                flash(f'Error removing port: {err}', 'error')
            else:
                flash(f'Removed port {port} from block list', 'success')
        
        return redirect(url_for('ports'))
        
    ports = xdp_wrapper.get_ports()
    return render_template('ports.html', ports=ports)

@app.route('/config', methods=['GET', 'POST'])
def config():
    if request.method == 'POST':
        for key in ['pps_limit', 'max_size', 'icmp_limit', 'syn_limit']:
            val = request.form.get(key)
            if val:
                err = xdp_wrapper.set_config(key, val)
                if err:
                    flash(f'Error setting {key}: {err}', 'error')
        
        flash('Configuration updated', 'success')
        return redirect(url_for('config'))
        
    config = xdp_wrapper.get_config()
    return render_template('config.html', config=config)

if __name__ == '__main__':
    # FIX: Make host/port configurable via environment
    host = os.environ.get('XDP_WEB_HOST', '127.0.0.1')
    port = int(os.environ.get('XDP_WEB_PORT', '5000'))
    debug = os.environ.get('XDP_WEB_DEBUG', 'false').lower() == 'true'
    app.run(host=host, port=port, debug=debug)
