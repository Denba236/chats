/**
 * Security Suite - Client Side Protection
 * Includes: XSS Protection, CSRF, CSP, Input Sanitization
 */

(function() {
    'use strict';

    const Security = {
        /**
         * Prevents the site from being embedded in an iframe (Anti-Clickjacking)
         */
        preventClickjacking: function() {
            if (window.self !== window.top) {
                window.top.location = window.self.location;
            }
        },

        /**
         * Deterrence against using DevTools (Right click, F12, etc.)
         * Note: This is security by obscurity and can be bypassed, but often requested.
         */
        deterDevTools: function() {
            // Disable right click
            document.addEventListener('contextmenu', function(e) {
                e.preventDefault();
            }, false);

            // Disable common DevTools shortcuts
            document.addEventListener('keydown', function(e) {
                // F12
                if (e.keyCode === 123) {
                    e.preventDefault();
                    return false;
                }
                // Ctrl+Shift+I (Inspect)
                if (e.ctrlKey && e.shiftKey && e.keyCode === 73) {
                    e.preventDefault();
                    return false;
                }
                // Ctrl+Shift+J (Console)
                if (e.ctrlKey && e.shiftKey && e.keyCode === 74) {
                    e.preventDefault();
                    return false;
                }
                // Ctrl+U (View Source)
                if (e.ctrlKey && e.keyCode === 85) {
                    e.preventDefault();
                    return false;
                }
            }, false);
        },

        /**
         * XSS Protection using DOMPurify if available
         */
        sanitizeHTML: function(html) {
            if (typeof DOMPurify !== 'undefined') {
                return DOMPurify.sanitize(html, {
                    USE_PROFILES: { html: true },
                    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'code', 'pre', 'blockquote'],
                    ALLOWED_ATTR: []
                });
            }
            // Fallback if DOMPurify not loaded
            const temp = document.createElement('div');
            temp.textContent = html;
            return temp.innerHTML;
        },

        /**
         * Basic sanitization for strings to prevent simple XSS
         */
        sanitizeString: function(str) {
            if (!str) return '';
            const temp = document.createElement('div');
            temp.textContent = str;
            return temp.innerHTML;
        },

        /**
         * Validates form inputs for common malicious patterns
         */
        validateInput: function(input) {
            const forbiddenPatterns = [
                /<script/i,
                /javascript:/i,
                /onerror=/i,
                /onload=/i,
                /onclick=/i,
                /onmouseover=/i,
                /<iframe/i,
                /<object/i,
                /<embed/i,
                /<link/i,
                /<meta/i,
                /expression\(/i,
                /url\(/i
            ];

            return !forbiddenPatterns.some(pattern => pattern.test(input));
        },

        /**
         * Encode HTML entities to prevent XSS
         */
        encodeHTML: function(str) {
            if (!str) return '';
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return str.replace(/[&<>"']/g, m => map[m]);
        },

        /**
         * Validate URL to prevent javascript: protocol
         */
        sanitizeURL: function(url) {
            if (!url) return '';
            const pattern = /^(https?:\/\/|\/)/i;
            if (pattern.test(url)) {
                return url;
            }
            return '';
        },

        /**
         * CSRF Token extraction from cookie
         */
        getCSRFToken: function() {
            const name = 'csrf_token=';
            const decodedCookie = decodeURIComponent(document.cookie);
            const ca = decodedCookie.split(';');
            for (let i = 0; i < ca.length; i++) {
                let c = ca[i].trim();
                if (c.indexOf(name) === 0) {
                    return c.substring(name.length);
                }
            }
            return null;
        },

        /**
         * Clears sensitive data from localStorage/sessionStorage on potential security events
         */
        clearSensitiveData: function() {
            // Can be called on logout or session timeout
            localStorage.clear();
            sessionStorage.clear();
        },

        /**
         * Detect potential XSS attacks in input
         */
        detectXSS: function(input) {
            const xssPatterns = [
                /<script.*?>.*?<\/script>/gi,
                /javascript\s*:/gi,
                /on\w+\s*=/gi,
                /<img[^>]+onerror/gi,
                /<svg[^>]+onload/gi,
                /expression\s*\(/gi,
                /url\s*\(/gi,
                /vbscript\s*:/gi
            ];

            for (const pattern of xssPatterns) {
                if (pattern.test(input)) {
                    console.warn('Potential XSS attack detected:', input);
                    return true;
                }
            }
            return false;
        },

        /**
         * Set security headers via meta tags (CSP, etc.)
         */
        setSecurityHeaders: function() {
            // Content Security Policy
            const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            if (!cspMeta) {
                const meta = document.createElement('meta');
                meta.httpEquiv = 'Content-Security-Policy';
                meta.content = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https:;";
                document.head.appendChild(meta);
            }

            // X-Content-Type-Options
            const xctoMeta = document.querySelector('meta[http-equiv="X-Content-Type-Options"]');
            if (!xctoMeta) {
                const meta = document.createElement('meta');
                meta.httpEquiv = 'X-Content-Type-Options';
                meta.content = 'nosniff';
                document.head.appendChild(meta);
            }

            // X-Frame-Options
            const xfoMeta = document.querySelector('meta[http-equiv="X-Frame-Options"]');
            if (!xfoMeta) {
                const meta = document.createElement('meta');
                meta.httpEquiv = 'X-Frame-Options';
                meta.content = 'SAMEORIGIN';
                document.head.appendChild(meta);
            }

            // X-XSS-Protection
            const xxssMeta = document.querySelector('meta[http-equiv="X-XSS-Protection"]');
            if (!xxssMeta) {
                const meta = document.createElement('meta');
                meta.httpEquiv = 'X-XSS-Protection';
                meta.content = '1; mode=block';
                document.head.appendChild(meta);
            }
        },

        /**
         * Initialize input security listeners
         */
        initInputSecurity: function() {
            document.querySelectorAll('input, textarea').forEach(input => {
                input.addEventListener('blur', function() {
                    if (Security.detectXSS(this.value)) {
                        console.warn('XSS attempt detected in input:', this.name);
                        this.value = Security.encodeHTML(this.value);
                    }
                });
            });
        },

        init: function() {
            this.setSecurityHeaders();
            this.preventClickjacking();
            this.deterDevTools();
            this.initInputSecurity();
            console.log("Security suite initialized with XSS, CSRF, and CSP protection.");
        }
    };

    // Initialize security measures
    window.AppSecurity = Security;
    Security.init();

})();
