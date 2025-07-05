const express = require('express');
const exphbs = require('express-handlebars');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const { exec } = require('child_process'); // For Command Injection
const http = require('http'); // For SSRF
const path = require('path'); // For Path Traversal
const _ = require('lodash'); // For potential prototype pollution (older versions)
const qs = require('qs'); // For potential prototype pollution (older versions)

// --- 3. Express App Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- 4. Handlebars Configuration ---
app.engine('handlebars', exphbs({
    defaultLayout: 'main',
    // Intentionally allowing prototype access for potential prototype pollution via Handlebars
    // This is generally a bad idea in production.
    allowedProtoProperties: true,
    allowedProtoMethods: true
}));
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views')); // Set views directory

// --- 5. Middleware (Insecurely Configured) ---
// A05:2021 - Security Misconfiguration: Using outdated body-parser, no security headers.
app.use(bodyParser.urlencoded({ extended: false })); // extended: false is slightly better, but still parsing everything
app.use(bodyParser.json()); // Allow JSON body parsing
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

// --- 6. SQLite Database Setup ---
// No separate database server, just a file-based SQLite DB.
// The database file will be created in the current directory if it doesn't exist.
const db = new sqlite3.Database('./terrible_app.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create products table and insert dummy data
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL,
                internal_cost REAL,
                is_active INTEGER DEFAULT 1
            )`);

            // Clear existing data for consistent state (for testing)
            db.run(`DELETE FROM products`);

            const stmt = db.prepare(`INSERT INTO products (name, description, price, internal_cost, is_active) VALUES (?, ?, ?, ?, ?)`);
            stmt.run('Vulnerable Widget', 'A widget with many security flaws.', 9.99, 5.00, 1);
            stmt.run('Insecure Gadget', 'This gadget will expose your data.', 19.99, 10.00, 1);
            stmt.run('Broken Device', 'Designed to fail security audits.', 29.99, 15.00, 0);
            stmt.run('Exploitable Tool', 'Easy to hack, fun for pentesters.', 39.99, 20.00, 1);
            stmt.finalize();
            console.log('Products table created and populated.');
        });
    }
});

// --- 7. Helper for rendering (to demonstrate XSS) ---
// A03:2021 - Injection (XSS): Helper that explicitly marks string as "safe" for Handlebars, bypassing default escaping.
// This is a common pattern for XSS in Handlebars when not used carefully.
const hbs = exphbs.create({});
hbs.handlebars.registerHelper('raw', function(content) { // Modified to accept content directly
    return content; // Renders content without escaping
});


// --- 8. Vulnerable Routes ---

// API1:2023 - Broken Object Level Authorization (BOLA) / A01:2021 - Broken Access Control
// API3:2023 - Broken Object Property Level Authorization
// Allows direct access to any product ID and exposes all properties, including internal_cost.
app.get('/product/:id', (req, res) => {
    const productId = req.params.id; // IDOR: No authorization check
    db.get(`SELECT * FROM products WHERE id = ${productId}`, (err, row) => { // A03:2021 - SQL Injection (if id was user input, but here it's from URL param)
        if (err) {
            // A05:2021 - Security Misconfiguration: Verbose error message
            return res.status(500).send(`Error retrieving product: ${err.message}`);
        }
        if (row) {
            // A06:2021 - Sensitive Data Exposure: Exposing internal_cost
            res.render('product-detail', { product: row });
        } else {
            res.status(404).send('Product not found.');
        }
    });
});

// A03:2021 - Injection (SQL Injection) & A06:2021 - Sensitive Data Exposure
// Search functionality vulnerable to SQL Injection.
app.get('/search', (req, res) => {
    const searchTerm = req.query.q || '';
    // SQL Injection: Directly concatenating user input into SQL query
    const sql = `SELECT id, name, description, price, internal_cost FROM products WHERE name LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`;

    console.log('Executing SQL (vulnerable):', sql); // A09:2021 - Security Logging Failure: Logging sensitive SQL

    db.all(sql, (err, rows) => {
        if (err) {
            return res.status(500).send(`Search error: ${err.message}`);
        }
        // A02:2021 - Cryptographic Failures / A06:2021 - Sensitive Data Exposure:
        // No encryption for sensitive data (internal_cost) even if it were passed around.
        res.render('search-results', {
            searchTerm: searchTerm,
            products: rows,
            // A03:2021 - XSS: Reflecting search term without proper encoding
            reflectedSearchTerm: `<script>alert('XSS on search: ${searchTerm}');</script>`
        });
    });
});

// A08:2021 - Software and Data Integrity Failures (Mass Assignment)
// Allows updating all product fields directly from user input.
app.post('/product/:id/update', (req, res) => {
    const productId = req.params.id;
    const { name, description, price, internal_cost, is_active } = req.body;

    // Mass Assignment: Directly using req.body to update fields without validation or whitelisting.
    // An attacker could potentially change `internal_cost` or `is_active` without authorization.
    const sql = `UPDATE products SET
        name = '${name}',
        description = '${description}',
        price = ${parseFloat(price) || 0},
        internal_cost = ${parseFloat(internal_cost) || 0},
        is_active = ${parseInt(is_active) || 0}
        WHERE id = ${productId}`;

    console.log('Executing SQL (vulnerable update):', sql);

    db.run(sql, function(err) {
        if (err) {
            return res.status(500).send(`Update error: ${err.message}`);
        }
        if (this.changes > 0) {
            res.redirect(`/product/${productId}?status=updated`);
        } else {
            res.status(404).send('Product not found or no changes.');
        }
    });
});

// A03:2021 - Injection (Command Injection)
// Allows executing arbitrary system commands.
app.get('/debug/exec', (req, res) => {
    const cmd = req.query.cmd;
    if (!cmd) {
        return res.status(400).send('Please provide a "cmd" query parameter.');
    }

    // Command Injection: Directly executing user-provided command
    exec(cmd, (err, stdout, stderr) => {
        if (err) {
            // A05:2021 - Security Misconfiguration: Verbose error messages
            return res.status(500).send(`<pre>Error executing command: ${err.message}\n${stderr}</pre>`);
        }
        res.send(`<pre>Command Output:\n${stdout}</pre>`);
    });
});

// A07:2021 - Server-Side Request Forgery (SSRF)
// Allows the server to make requests to arbitrary URLs.
app.get('/debug/fetch', (req, res) => {
    const url = req.query.url;
    if (!url) {
        return res.status(400).send('Please provide a "url" query parameter.');
    }

    // SSRF: Server fetches arbitrary URL provided by user
    http.get(url, (response) => {
        let data = '';
        response.on('data', (chunk) => {
            data += chunk;
        });
        response.on('end', () => {
            res.send(`<pre>Fetched content from ${url}:\n${data}</pre>`);
        });
    }).on('error', (err) => {
        // A05:2021 - Security Misconfiguration: Verbose error messages
        res.status(500).send(`Error fetching URL: ${err.message}`);
    });
});

// A01:2021 - Broken Access Control (IDOR for deletion)
app.get('/product/:id/delete', (req, res) => {
    const productId = req.params.id;
    // IDOR: No authorization check before deleting
    db.run(`DELETE FROM products WHERE id = ${productId}`, function(err) {
        if (err) {
            return res.status(500).send(`Deletion error: ${err.message}`);
        }
        if (this.changes > 0) {
            res.send(`Product ${productId} deleted.`);
        } else {
            res.status(404).send('Product not found for deletion.');
        }
    });
});

// A03:2021 - XSS (Stored XSS via product description)
// A08:2021 - Software and Data Integrity Failures (Mass Assignment on create)
app.get('/add-product', (req, res) => {
    res.render('add-product');
});

app.post('/add-product', (req, res) => {
    const { name, description, price, internal_cost, is_active } = req.body;

    // Mass Assignment: Directly using req.body without validation or whitelisting
    // Stored XSS: description is saved directly and rendered unescaped later
    const sql = `INSERT INTO products (name, description, price, internal_cost, is_active) VALUES (?, ?, ?, ?, ?)`;
    db.run(sql, [name, description, parseFloat(price) || 0, parseFloat(internal_cost) || 0, parseInt(is_active) || 0], function(err) {
        if (err) {
            return res.status(500).send(`Error adding product: ${err.message}`);
        }
        res.redirect(`/product/${this.lastID}?status=added`);
    });
});

// Home Page - Lists all products
app.get('/', (req, res) => {
    db.all("SELECT id, name, description, price FROM products", (err, rows) => {
        if (err) {
            return res.status(500).send(`Error listing products: ${err.message}`);
        }
        res.render('home', { products: rows });
    });
});

// --- 9. Error Handling (Minimal and Verbose) ---
// A05:2021 - Security Misconfiguration: Exposing stack traces
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke! Check server logs for details.');
});

// --- 10. Start the Server ---
app.listen(PORT, () => {
    console.log(`Terrible app running on http://localhost:${PORT}`);
    console.log('--- VULNERABILITIES TO EXPLORE ---');
    console.log('1. SQL Injection: /search?q=<inject_here> (e.g., %\' OR 1=1-- )');
    console.log('2. XSS (Reflected): /search?q=<script>alert(document.domain)</script>');
    console.log('3. XSS (Stored): Add a product with <script>alert("Stored XSS!");</script> in description.');
    console.log('4. Command Injection: /debug/exec?cmd=ls%20-la (Linux) or /debug/exec?cmd=dir (Windows)');
    console.log('5. SSRF: /debug/fetch?url=http://localhost:3000/ (fetch itself) or /debug/fetch?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)');
    console.log('6. IDOR/Broken Access Control: Directly access /product/:id/delete or /product/:id/update without auth.');
    console.log('7. Mass Assignment: Use /product/:id/update or /add-product to send unexpected fields (e.g., is_admin if it existed).');
    console.log('8. Sensitive Data Exposure: internal_cost is visible on product details and search results.');
    console.log('9. Outdated Components: Run npm audit after npm install.');
    console.log('10. Security Misconfiguration: Verbose errors, no security headers (Helmet is not used).');
});