from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_POST
from django.db.models import Sum
from decimal import Decimal, ROUND_HALF_UP
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from django.conf import settings
import tempfile
import os
from io import BytesIO
import subprocess
import base64
import json
from pathlib import Path
from datetime import date


def _extract_payment_terms_from_notes(invoice):
    """Extract payment terms from invoice notes field."""
    if invoice.notes:
        lines = invoice.notes.split('\n')
        for line in lines:
            if line.startswith('Payment Terms:'):
                return line.replace('Payment Terms:', '').strip()
    
    # Fallback to tranche option if no payment terms in notes
    if invoice.tranche and invoice.tranche.tranche_record:
        return invoice.tranche.tranche_record.tranche_option
    
    return "Combined Tranches"


def _compute(invoice):
    """Calculate amounts based on net commission (unit_price) and withholding tax rate."""
    qty = invoice.qty
    net_comm = invoice.unit_price  # Net Commission per unit
    tax_rate = invoice.vat_rate / Decimal("100")  # withholding tax rate (e.g. 0.10)

    tax_amount = (net_comm * tax_rate).quantize(Decimal("0.01"))
    expected_comm = (net_comm - tax_amount).quantize(Decimal("0.01"))

    return {
        "qty": qty,
        "net_price": net_comm,
        "vat_amount": tax_amount,
        "subtotal": expected_comm,
    }
from django.contrib.auth.decorators import login_required
from django.utils.timezone import now

from .models import BillingInvoice, TranchePayment

__all__ = [
    "generate_invoice_number",
    "invoice_view",
    "create_invoice",
    "invoice_pdf",
    "invoice_csv",
    "email_invoice",
    "sign_invoice",
    "upload_signature",
]


def _get_default_signature_url(role):
    """Get the URL for default signature based on role."""
    import os
    from django.conf import settings
    from django.templatetags.static import static
    
    # Map roles to default signature filenames
    default_signatures = {
        'prepared_by': 'shiela-esign.jpeg',
        'checked_by': 'cha-esign.jpeg', 
        'approved_by': 'gab-esign.jpeg'
    }
    
    if role not in default_signatures:
        return None
    
    # Check if file exists in static/media directory
    filename = default_signatures[role]
    static_path = os.path.join(settings.BASE_DIR, 'sparc', 'static', 'media', filename)
    
    if os.path.exists(static_path):
        return static(f'media/{filename}')
    
    return None


def _get_signature_url_or_default(invoice, role):
    """Get signature URL from invoice field or return default signature URL."""
    # Get the signature field for this role
    signature_field = getattr(invoice, f"{role}_signature", None)
    
    # If signature exists and has a file, return its URL
    if signature_field and signature_field.name:
        return signature_field.url
    
    # Otherwise return default signature URL
    return _get_default_signature_url(role)


def _generate_invoice_image(html_content, invoice_no):
    """Generate a high-quality PNG image from HTML invoice content.
    
    Args:
        html_content (str): The complete HTML content of the invoice
        invoice_no (str): Invoice number for filename
        
    Returns:
        bytes: PNG image data, or None if generation fails
    """
    try:
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as html_file:
            # Prepare HTML with print-optimized CSS
            optimized_html = _prepare_html_for_image(html_content)
            html_file.write(optimized_html)
            html_file.flush()
            
            # Generate PNG using wkhtmltoimage
            output_path = html_file.name.replace('.html', '.png')
            
            # Get the executable path from settings
            executable = getattr(settings, 'WKHTMLTOIMAGE_PATH', 'wkhtmltoimage')

            # Explicitly check if the executable file exists before trying to run it
            if not os.path.exists(executable):
                print(f"FATAL: wkhtmltoimage executable not found at the specified path: {executable}")
                return _generate_invoice_image_weasyprint(html_content, invoice_no)

            # wkhtmltoimage command with high-quality settings
            cmd = [
                executable,
                '--format', 'png',
                '--quality', '100',
                '--width', '1200',
                '--height', '1600',
                '--disable-smart-width',
                '--encoding', 'UTF-8',
                '--javascript-delay', '1000',
                '--no-stop-slow-scripts',
                '--debug-javascript',
                '--enable-local-file-access',
                html_file.name,
                output_path
            ]
            
            # Execute wkhtmltoimage and catch potential FileNotFoundError
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            except FileNotFoundError:
                print(f"FATAL: The system could not find the executable, even though it exists at: {executable}. This might be a permissions issue.")
                return _generate_invoice_image_weasyprint(html_content, invoice_no)

            # Check for errors and log them
            if result.returncode != 0:
                error_log = result.stderr.strip()
                print(f"wkhtmltoimage error: {error_log}")
                # Try the fallback method
                return _generate_invoice_image_weasyprint(html_content, invoice_no)

            if os.path.exists(html_file.name.replace('.html', '.png')):
                # Read the generated PNG
                with open(html_file.name.replace('.html', '.png'), 'rb') as img_file:
                    image_data = img_file.read()
                
                # Clean up temporary files
                try:
                    os.unlink(html_file.name)
                    os.unlink(output_path)
                except OSError:
                    pass
                    
                return image_data
            else:
                print(f"wkhtmltoimage failed: {result.stderr}")
                return None
                
    except subprocess.TimeoutExpired:
        print("wkhtmltoimage timed out")
        return None
    except FileNotFoundError:
        print("wkhtmltoimage not found. Please install wkhtmltopdf package.")
        # Fallback to weasyprint method
        return _generate_invoice_image_weasyprint(html_content, invoice_no)
    except Exception as e:
        print(f"Error generating invoice image: {e}")
        return None


def _clean_html_for_pdf(html_content, logo_path=None):
    """Clean HTML content for PDF generation while preserving styling.
    
    Args:
        html_content (str): Original HTML content from invoice template
        logo_path (str): Path to company logo file
        
    Returns:
        str: Processed HTML ready for PDF generation
    """
    import re
    
    # Remove interactive elements that don't work in PDF
    html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL)
    html_content = re.sub(r'<script[^>]*src="[^"]*"[^>]*></script>', '', html_content)
    
    # Replace logo src with file path if available
    if logo_path:
        # Use raw string and escape backslashes for Windows paths
        logo_file_url = f'file:///{logo_path.replace(chr(92), "/")}'
        html_content = re.sub(
            r'src="[^"]*static[^"]*LOGO\.png[^"]*"',
            f'src="{logo_file_url}"',
            html_content
        )
    
    # Remove the extends and block tags since we're rendering standalone
    html_content = re.sub(r'{%\s*extends[^%]*%}', '', html_content)
    html_content = re.sub(r'{%\s*block[^%]*%}', '', html_content)
    html_content = re.sub(r'{%\s*endblock[^%]*%}', '', html_content)
    
    # Remove no-print elements
    html_content = re.sub(r'<[^>]*class="[^"]*no-print[^"]*"[^>]*>.*?</[^>]*>', '', html_content, flags=re.DOTALL)
    
    # Add comprehensive Tailwind CSS replacement to match original template styling
    return html_content


def _prepare_html_with_tailwind(html_content, logo_path=None):
    """Prepare HTML with embedded Tailwind CSS for pixel-perfect PDF generation."""
    import re
    
    # Remove scripts and external dependencies
    html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL)
    html_content = re.sub(r'<script[^>]*src="[^"]*"[^>]*></script>', '', html_content)
    
    # Remove navbar and sidebar elements that appear in PDF
    html_content = re.sub(r'{% if user\.is_authenticated %}.*?{% include \'navbar\.html\' %}.*?{% endif %}', '', html_content, flags=re.DOTALL)
    html_content = re.sub(r'<div class="max-w-\[calc\(100%-1rem\)\] ml-60[^>]*>', '<div class="max-w-4xl mx-auto">', html_content)
    
    # Replace logo path for PDF
    if logo_path:
        logo_file_url = f'file:///{logo_path.replace(chr(92), "/")}'
        html_content = re.sub(
            r'src="[^"]*static[^"]*LOGO\.png[^"]*"',
            f'src="{logo_file_url}"',
            html_content
        )
    
    # Remove template tags
    html_content = re.sub(r'{%\s*extends[^%]*%}', '', html_content)
    html_content = re.sub(r'{%\s*block[^%]*%}', '', html_content)
    html_content = re.sub(r'{%\s*endblock[^%]*%}', '', html_content)
    
    # Embed complete Tailwind CSS
    tailwind_css = """
    <style>
        @page {
            size: A4;
            margin: 0.5in;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }
        
        /* Reset and base styles */
        * { 
            box-sizing: border-box; 
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            color-adjust: exact !important;
        }
        
        body { 
            margin: 0; 
            padding: 0; 
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f3f4f6;
            color: #1f2937;
        }
        
        /* Layout utilities */
        .max-w-4xl { max-width: 56rem; margin: 0 auto; }
        .mx-auto { margin-left: auto; margin-right: auto; }
        .my-10 { margin-top: 2.5rem; margin-bottom: 2.5rem; }
        .p-8 { padding: 2rem; }
        .p-6 { padding: 1.5rem; }
        .p-4 { padding: 1rem; }
        .p-3 { padding: 0.75rem; }
        .p-2 { padding: 0.5rem; }
        .px-6 { padding-left: 1.5rem; padding-right: 1.5rem; }
        .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
        .px-2 { padding-left: 0.5rem; padding-right: 0.5rem; }
        .py-1 { padding-top: 0.25rem; padding-bottom: 0.25rem; }
        .py-0-5 { padding-top: 0.125rem; padding-bottom: 0.125rem; }
        .pb-6 { padding-bottom: 1.5rem; }
        .pt-6 { padding-top: 1.5rem; }
        .pl-4 { padding-left: 1rem; }
        .pr-4 { padding-right: 1rem; }
        .mt-4 { margin-top: 1rem; }
        .mt-6 { margin-top: 1.5rem; }
        .mt-8 { margin-top: 2rem; }
        .mt-2 { margin-top: 0.5rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-4 { margin-bottom: 1rem; }
        .mb-8 { margin-bottom: 2rem; }
        .mr-4 { margin-right: 1rem; }
        .mr-2 { margin-right: 0.5rem; }
        .mr-1 { margin-right: 0.25rem; }
        .ml-1 { margin-left: 0.25rem; }
        
        /* Flexbox */
        .flex { display: flex; }
        .justify-between { justify-content: space-between; }
        .justify-center { justify-content: center; }
        .items-start { align-items: flex-start; }
        .items-center { align-items: center; }
        
        /* Grid */
        .grid { display: grid; }
        .grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .gap-8 { gap: 2rem; }
        .gap-6 { gap: 1.5rem; }
        .gap-4 { gap: 1rem; }
        
        /* Typography */
        .text-2xl { font-size: 1.5rem; line-height: 2rem; }
        .text-xl { font-size: 1.25rem; line-height: 1.75rem; }
        .text-lg { font-size: 1.125rem; line-height: 1.75rem; }
        .text-sm { font-size: 0.875rem; line-height: 1.25rem; }
        .text-xs { font-size: 0.75rem; line-height: 1rem; }
        .font-bold { font-weight: 700; }
        .font-semibold { font-weight: 600; }
        .font-medium { font-weight: 500; }
        .text-center { text-align: center; }
        .text-right { text-align: right; }
        .text-left { text-align: left; }
        
        /* Colors */
        .bg-white { background-color: #ffffff; }
        .bg-gray-100 { background-color: #f3f4f6; }
        .bg-gray-50 { background-color: #f9fafb; }
        .bg-blue-600 { background-color: #2563eb; }
        .bg-blue-50 { background-color: #eff6ff; }
        .bg-green-100 { background-color: #dcfce7; }
        .bg-yellow-100 { background-color: #fef3c7; }
        .text-white { color: #ffffff; }
        .text-gray-800 { color: #1f2937; }
        .text-gray-600 { color: #4b5563; }
        .text-gray-500 { color: #6b7280; }
        .text-gray-400 { color: #9ca3af; }
        .text-blue-600 { color: #2563eb; }
        .text-green-800 { color: #166534; }
        .text-yellow-800 { color: #92400e; }
        .text-blue-800 { color: #1e40af; }
        
        /* Borders */
        .border { border-width: 1px; }
        .border-b { border-bottom-width: 1px; }
        .border-b-2 { border-bottom-width: 2px; }
        .border-l-4 { border-left-width: 4px; }
        .border-t { border-top-width: 1px; }
        .border-t-2 { border-top-width: 2px; }
        .border-gray-200 { border-color: #e5e7eb; }
        .border-gray-300 { border-color: #d1d5db; }
        .border-blue-600 { border-color: #2563eb; }
        .border-blue-500 { border-color: #3b82f6; }
        
        /* Rounded corners */
        .rounded-lg { border-radius: 0.5rem; }
        .rounded-md { border-radius: 0.375rem; }
        .rounded-full { border-radius: 9999px; }
        
        /* Shadows */
        .shadow-2xl { box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); }
        .shadow-lg { box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05); }
        .shadow-md { box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); }
        
        /* Display */
        .hidden { display: none; }
        .inline-block { display: inline-block; }
        .block { display: block; }
        
        /* Width/Height */
        .w-full { width: 100%; }
        .h-16 { height: 4rem; }
        .w-auto { width: auto; }
        .w-4 { width: 1rem; }
        
        /* Spacing */
        .space-y-2 > * + * { margin-top: 0.5rem; }
        .space-y-1 > * + * { margin-top: 0.25rem; }
        .space-x-4 > * + * { margin-left: 1rem; }
        
        /* Table styles */
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: left; }
        
        /* Whitespace */
        .whitespace-pre-line { white-space: pre-line; }
        
        /* Font sans */
        .font-sans { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
        
        /* Print specific - but show blue box in PDF */
        .no-print { display: none !important; }
        .no-print.bg-blue-600 { display: block !important; }
        
        /* Header specific styles - complete layout match */
        .max-w-4xl {
            max-width: 56rem;
            margin: 0 auto;
            padding: 2rem;
            background-color: white;
            border-radius: 0.5rem;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }
        
        header { 
            display: flex !important; 
            justify-content: space-between !important; 
            align-items: flex-start !important; 
            padding-bottom: 1.5rem !important; 
            border-bottom: 2px solid #e5e7eb !important; 
            margin-bottom: 1.5rem !important;
        }
        
        header > div:first-child {
            display: flex !important;
            align-items: center !important;
        }
        
        header img {
            height: 4rem !important;
            width: auto !important;
            margin-right: 1rem !important;
            display: block !important;
        }
        
        header > div:first-child > div {
            display: block !important;
        }
        
        header h1 {
            font-size: 1.5rem !important;
            font-weight: 700 !important;
            color: #1f2937 !important;
            margin: 0 !important;
            line-height: 1.2 !important;
        }
        
        header .text-sm {
            font-size: 0.875rem !important;
            color: #2563eb !important;
            font-weight: 600 !important;
            margin: 0.25rem 0 0 0 !important;
            display: block !important;
        }
        
        header .mt-4 {
            margin-top: 1rem !important;
        }
        
        header .text-xs {
            font-size: 0.75rem !important;
            color: #6b7280 !important;
            line-height: 1.4 !important;
        }
        
        header .text-xs p {
            margin: 0 0 0.5rem 0 !important;
            display: flex !important;
            align-items: center !important;
        }
        
        header .text-xs i {
            width: 1rem !important;
            margin-right: 0.25rem !important;
            text-align: center !important;
        }
        
        header > div:last-child {
            text-align: right !important;
        }
        
        /* Blue BILLING STATEMENT box - force visibility */
        .bg-blue-600,
        header .bg-blue-600,
        header div.bg-blue-600,
        [class*="bg-blue-600"] {
            background-color: #2563eb !important;
            color: white !important;
            padding: 0.5rem 1.5rem !important;
            font-weight: 700 !important;
            font-size: 1.125rem !important;
            border-radius: 0.375rem !important;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1) !important;
            margin-bottom: 1rem !important;
            display: block !important;
            text-align: center !important;
            visibility: visible !important;
            opacity: 1 !important;
        }
        
        /* Invoice number box */
        header div[class*="bg-gray-50"] {
            background-color: #f9fafb !important;
            border: 1px solid #d1d5db !important;
            border-radius: 0.375rem !important;
            padding: 0.75rem !important;
            margin-top: 0 !important;
            display: block !important;
        }
        
        header .bg-gray-50 p:first-child {
            font-size: 0.75rem !important;
            font-weight: 600 !important;
            color: #6b7280 !important;
            margin: 0 0 0.25rem 0 !important;
        }
        
        header .bg-gray-50 p:last-child {
            font-size: 1.25rem !important;
            font-weight: 700 !important;
            color: #1f2937 !important;
            margin: 0 !important;
        }
        
        /* Footer specific styles */
        footer {
            text-align: center;
            font-size: 0.75rem;
            color: #6b7280;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 2px solid #e5e7eb;
        }
        
        footer .flex.justify-center {
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: 0.5rem;
        }
        
        footer .space-x-4 > * + * {
            margin-left: 1rem;
        }
        
        /* Status badges */
        .bg-green-100.text-green-800 {
            background-color: #dcfce7;
            color: #166534;
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .bg-yellow-100.text-yellow-800 {
            background-color: #fef3c7;
            color: #92400e;
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .bg-blue-100.text-blue-800 {
            background-color: #dbeafe;
            color: #1e40af;
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
    </style>
    """
    
    # Complete the CSS with closing tag
    tailwind_css += "</style>"
    
    # Insert CSS before closing head tag or create head if it doesn't exist
    if '</head>' in html_content:
        html_content = html_content.replace('</head>', f'{tailwind_css}</head>')
    else:
        # Find the opening body tag and insert head before it
        if '<body' in html_content:
            html_content = html_content.replace('<body', f'<head>{tailwind_css}</head><body')
        else:
            html_content = f'<head>{tailwind_css}</head>{html_content}'
    
    return html_content


def _prepare_html_for_image(html_content):
    """Optimize HTML content for high-quality image generation.
    
    Args:
        html_content (str): Original HTML content
        
    Returns:
        str: Optimized HTML with print-specific CSS
    """
    # Add print-optimized CSS
    print_css = """
    <style>
        @media print, screen {
            html, body {
                -webkit-print-color-adjust: exact !important;
                color-adjust: exact !important;
                print-color-adjust: exact !important;
                background: white !important;
                font-family: system-ui, -apple-system, sans-serif !important;
                margin: 0 !important;
                padding: 0 !important;
            }
            .max-w-4xl {
                max-width: 1024px !important; /* Tailwind's max-w-4xl is 56rem = 896px, but we give it more room */
                margin: 0 auto !important;
            }
            .no-print, .btn-sig, .btn-sig-clear {
                display: none !important;
            }
            .bg-blue-600 {
                background-color: #2563eb !important;
            }
            .text-blue-600 {
                color: #2563eb !important;
            }
            .border-blue-600 {
                border-color: #2563eb !important;
            }
            .bg-amber-50 {
                background-color: #fffbeb !important;
            }
            .border-amber-400 {
                border-color: #f59e0b !important;
            }
            .text-amber-500 {
                color: #f59e0b !important;
            }
            .text-gray-800 { color: #1f2937 !important; }
            .text-gray-600 { color: #4b5563 !important; }
            .text-gray-500 { color: #6b7280 !important; }
            .bg-gray-50 { background-color: #f9fafb !important; }
            .border-gray-200 { border-color: #e5e7eb !important; }
            .signature-container img {
                max-height: 64px !important;
                display: block !important;
            }
        }
    </style>
    """
    
    # Insert the print CSS before the closing head tag
    if '</head>' in html_content:
        html_content = html_content.replace('</head>', f'{print_css}</head>')
    else:
        # If no head tag, add it
        html_content = f'<head>{print_css}</head>' + html_content
    
    return html_content


def _generate_invoice_image_weasyprint(html_content, invoice_no):
    """Fallback method using WeasyPrint to generate PNG image.
    
    Args:
        html_content (str): The complete HTML content
        invoice_no (str): Invoice number for filename
        
    Returns:
        bytes: PNG image data, or None if generation fails
    """
    try:
        from weasyprint import HTML

        # Prepare HTML for WeasyPrint
        optimized_html = _prepare_html_for_image(html_content)

        # Use WeasyPrint to write directly to a PNG in memory
        # This removes the dependency on pdf2image and poppler
        png_buffer = BytesIO()
        HTML(string=optimized_html).write_png(png_buffer)
        png_buffer.seek(0)
        image_data = png_buffer.read()

        if image_data:
            return image_data
        else:
            print("WeasyPrint fallback failed to generate image data.")
            return None

    except ImportError:
        print("WeasyPrint library not found. Cannot generate image.")
        return None
    except Exception as e:
        # Catching other potential errors from WeasyPrint
        print(f"An error occurred during the WeasyPrint fallback: {e}")
        return None


def generate_invoice_number() -> str:
    """Return next incremental invoice number formatted as BI00000001, BI00000002, ..."""
    last = BillingInvoice.objects.order_by('-id').first()
    if last and last.invoice_no.startswith('BI') and last.invoice_no[2:].isdigit():
        next_num = int(last.invoice_no[2:]) + 1
    else:
        next_num = 1
    return f"BI{next_num:08d}"


@login_required
def create_invoice(request, tranche_id):
    """Create invoice for given TranchePayment and redirect to invoice page."""
    tranche = get_object_or_404(TranchePayment, pk=tranche_id)
    existing = tranche.invoices.first()
    if existing:
        return redirect('invoice_view', invoice_id=existing.id)

    # The reference number can be based on the tranche record ID for uniqueness
    reference_no = f"Tranche-{tranche.tranche_record.id}"

    # Get exact tranche data as calculated in view_tranche
    tranche_data = _get_tranche_data_for_invoice(tranche)
    
    # Use the exact values from tranche calculation
    unit_price = tranche_data['net_amount']
    if tranche.is_lto:
        vat_rate = tranche.tranche_record.option2_tax_rate
    else:
        vat_rate = tranche.tranche_record.option1_tax_rate

    # Get developer data for Bill To section
    client_name = "Client Name"
    client_address = "Client Address"
    client_tin = "Client TIN"
    
    try:
        from .models import Property
        property_obj = Property.objects.filter(name=tranche.tranche_record.project_name).first()
        if property_obj and property_obj.developer:
            developer = property_obj.developer
            client_name = developer.name
            client_address = developer.address or ""
            client_tin = developer.tin_number or ""
    except Exception as e:
        print(f"Warning: Could not get developer data for invoice: {e}")

    invoice = BillingInvoice.objects.create(
        tranche=tranche,
        invoice_no=generate_invoice_number(),
        reference_no=f"Billing Statement {reference_no}",
        issue_date=tranche.tranche_record.reservation_date,
        due_date=tranche.expected_date,
        unit_price=unit_price,
        vat_rate=vat_rate,
        client_name=client_name,
        client_address=client_address,
        client_tin=client_tin,
        prepared_by=request.user,
        prepared_by_date=now()
    )
    return redirect('invoice_view', invoice_id=invoice.id)


@login_required
def create_combined_invoice(request):
    """Create a combined invoice for multiple selected tranches."""
    if request.method != 'POST':
        messages.error(request, 'Invalid request method.')
        return redirect('tranche_history')
    
    tranche_ids_str = request.POST.get('tranche_ids', '')
    if not tranche_ids_str:
        messages.error(request, 'No tranches selected.')
        return redirect('tranche_history')
    
    try:
        tranche_ids = [int(id.strip()) for id in tranche_ids_str.split(',') if id.strip()]
    except ValueError:
        messages.error(request, 'Invalid tranche IDs.')
        return redirect('tranche_history')
    
    if len(tranche_ids) < 1:
        messages.error(request, 'Please select at least one tranche.')
        return redirect('tranche_history')
    
    # Fetch all selected tranches
    tranches = TranchePayment.objects.filter(id__in=tranche_ids).select_related('tranche_record')
    
    if not tranches.exists():
        messages.error(request, 'Selected tranches not found.')
        return redirect('tranche_history')
    
    # Get the tranche record for redirect purposes
    tranche_record = tranches.first().tranche_record
    tranche_record_id = tranche_record.id
    
    # Verify all tranches belong to the same tranche record
    if not all(t.tranche_record.id == tranche_record_id for t in tranches):
        messages.error(request, 'All selected tranches must belong to the same project.')
        return redirect('view_tranche', tranche_id=tranche_record_id)
    
    # Check if any of the selected tranches already have invoices
    existing_invoices = []
    original_count = len(tranches)
    
    for tranche in tranches:
        existing = tranche.invoices.first()
        if existing:
            existing_invoices.append(f"Tranche #{tranche.tranche_number} ({existing.invoice_no})")
    
    if existing_invoices:
        print(f"DEBUG: Found existing invoices: {existing_invoices}")
        # Instead of filtering, let's allow combined invoices even if some tranches have invoices
        # This is more user-friendly
        messages.warning(request, f'Note: Some selected tranches already have invoices: {", ".join(existing_invoices)}. Proceeding with combined invoice for all selected tranches.')
    
    # Remove the filter that was causing issues
    # tranches = tranches.filter(invoices__isnull=True)
    
    # if not tranches.exists():
    #     messages.error(request, 'All selected tranches already have invoices.')
    #     return redirect('view_tranche', tranche_id=tranche_record_id)
    
    # Debug: Add logging to see what's happening
    print(f"DEBUG: Creating combined invoice for {len(tranches)} tranches")
    print(f"DEBUG: Tranche IDs: {[t.id for t in tranches]}")
    print(f"DEBUG: Tranche Record ID: {tranche_record_id}")
    
    # Calculate combined totals based on Expected Commission from tranche view table
    total_expected_amount = sum(t.expected_amount for t in tranches)
    total_received_amount = sum(t.received_amount or Decimal('0') for t in tranches)
    
    # Use the earliest expected date as due date
    earliest_due_date = min(t.expected_date for t in tranches)
    
    # Create the combined invoice using the first tranche as primary
    primary_tranche = tranches.first()
    reference_no = f"Combined-Tranche-{tranche_record.id}"
    
    # Calculate combined unit price (net commission before tax) using Expected Commission logic
    try:
        combined_net_commission = Decimal('0.00')
        for tranche in tranches:
            # Get exact tranche data as calculated in view_tranche
            tranche_data = _get_tranche_data_for_invoice(tranche)
            combined_net_commission += tranche_data['net_amount']
        
        combined_unit_price = combined_net_commission.quantize(Decimal('0.01'))
        
        print(f"DEBUG: About to create invoice with unit_price: {combined_unit_price}")
        
        # Get developer data for Bill To section from primary tranche
        client_name = "Client Name"
        client_address = "Client Address"
        client_tin = "Client TIN"
        
        try:
            from .models import Property
            property_obj = Property.objects.filter(name=primary_tranche.tranche_record.project_name).first()
            if property_obj and property_obj.developer:
                developer = property_obj.developer
                client_name = developer.name
                client_address = developer.address or ""
                client_tin = developer.tin_number or ""
        except Exception as e:
            print(f"Warning: Could not get developer data for combined invoice: {e}")

        invoice = BillingInvoice.objects.create(
            tranche=primary_tranche,  # Primary tranche for reference
            invoice_no=generate_invoice_number(),
            reference_no=f"BILLING STATEMENT {reference_no}",
            issue_date=primary_tranche.tranche_record.reservation_date,
            due_date=earliest_due_date,
            unit_price=combined_unit_price,
            vat_rate=primary_tranche.tranche_record.option1_tax_rate if not primary_tranche.is_lto else primary_tranche.tranche_record.option2_tax_rate,
            client_name=client_name,
            client_address=client_address,
            client_tin=client_tin,
            prepared_by=request.user,
            prepared_by_date=now(),
            # Store additional data for combined invoice
            qty=len(tranches),  # Number of tranches combined
        )
        
        print(f"DEBUG: Invoice created successfully with ID: {invoice.id}")
        
        # Store the combined tranche IDs in the invoice notes field for reference
        combined_tranche_ids = ','.join(str(t.id) for t in tranches)
        invoice.notes = f"Combined invoice for tranches: {combined_tranche_ids}"
        invoice.save()
        
        print(f"DEBUG: Invoice notes updated: {invoice.notes}")
        
        # Don't create individual invoices for now - this might be causing issues
        # Just mark the tranches as having this invoice by updating their status or adding a note
        
        messages.success(request, f'Combined invoice {invoice.invoice_no} created successfully for {len(tranches)} tranches.')
        print(f"DEBUG: Redirecting to invoice_view with ID: {invoice.id}")
        return redirect('invoice_view', invoice_id=invoice.id)
        
    except Exception as e:
        print(f"DEBUG: Error creating invoice: {str(e)}")
        messages.error(request, f'Error creating combined invoice: {str(e)}')
        return redirect('view_tranche', tranche_id=tranche_record_id)


def _get_dp_tranche_data_from_view_logic(record):
    """Get DP tranche data using exact view_tranche calculation logic."""
    # Use the updated calculation logic that matches views.py
    # Two calculation paths based on Net of VAT input
    if record.net_of_vat_amount and record.net_of_vat_amount > 0:
        # Path 1: Use Net of VAT divisor calculation
        net_of_vat_base = (Decimal(str(record.total_contract_price)) / Decimal(str(record.net_of_vat_amount))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
        total_selling_price = net_of_vat_base - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
    else:
        # Path 2: Use Total Contract Price directly when Net of VAT is 0 or empty
        net_of_vat_base = record.total_contract_price
        less_process_fee = record.total_contract_price * (record.process_fee_percentage / Decimal(100))
        total_selling_price = record.total_contract_price - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))

    # Common calculations for both paths
    tax_rate = record.withholding_tax_rate / Decimal(100)
    vat_rate_decimal = record.vat_rate / Decimal(100)
    
    # Calculate VAT and Net of VAT from gross commission
    vat_amount = gross_commission * vat_rate_decimal
    net_of_vat = gross_commission - vat_amount
    
    # Calculate withholding tax and final net commission
    tax = net_of_vat * tax_rate
    net_commission = net_of_vat - tax
    
    # Calculate option1 values (DP period)
    option1_value_before_deduction = net_commission * (record.option1_percentage / Decimal(100))
    option1_tax_rate = record.option1_tax_rate / Decimal(100)
    
    # Apply deductions
    deduction_tax_rate = record.deduction_tax_rate / Decimal(100)
    deduction_tax = record.other_deductions * deduction_tax_rate
    deduction_net = record.other_deductions - deduction_tax
    
    option1_value = option1_value_before_deduction - deduction_net
    option1_monthly = option1_value / Decimal(record.number_months)
    
    # Individual tranche values - exact same as view_tranche lines 3742-3744
    # NO quantization here to match views.py exactly
    net = option1_monthly
    tax_amount = net * option1_tax_rate
    expected_commission = net - tax_amount
    
    return {
        'net_amount': net,
        'tax_amount': tax_amount,
        'expected_commission': expected_commission
    }


def _get_lto_tranche_data_from_view_logic(record):
    """Get LTO tranche data using exact view_tranche calculation logic."""
    # Use the updated calculation logic that matches views.py
    # Two calculation paths based on Net of VAT input
    if record.net_of_vat_amount and record.net_of_vat_amount > 0:
        # Path 1: Use Net of VAT divisor calculation
        net_of_vat_base = (Decimal(str(record.total_contract_price)) / Decimal(str(record.net_of_vat_amount))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
        total_selling_price = net_of_vat_base - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
    else:
        # Path 2: Use Total Contract Price directly when Net of VAT is 0 or empty
        net_of_vat_base = record.total_contract_price
        less_process_fee = record.total_contract_price * (record.process_fee_percentage / Decimal(100))
        total_selling_price = record.total_contract_price - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))

    # Common calculations for both paths
    tax_rate = record.withholding_tax_rate / Decimal(100)
    vat_rate_decimal = record.vat_rate / Decimal(100)
    
    # Calculate VAT and Net of VAT from gross commission
    vat_amount = gross_commission * vat_rate_decimal
    net_of_vat = gross_commission - vat_amount
    
    # Calculate withholding tax and final net commission
    tax = net_of_vat * tax_rate
    net_commission = net_of_vat - tax
    
    # Calculate LTO values - exact same as view_tranche lines 2914-2922
    option2_value = net_commission * (record.option2_percentage / Decimal(100))
    option2_tax_rate = record.option2_tax_rate / Decimal(100)
    lto_deduction_value = option2_value
    lto_deduction_tax = lto_deduction_value * option2_tax_rate
    lto_deduction_net = lto_deduction_value - lto_deduction_tax
    
    
    # CRITICAL: Match the exact display mapping from LTO schedule table
    # LTO Schedule shows: Net Commission (before tax), Less Tax, Expected Commission (after tax)
    # Invoice needs: Commission (before tax), Less Tax, Total Due (after tax)
    return {
        'net_amount': lto_deduction_value.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP),     # Commission = ₱23,102.68 (before tax)
        'tax_amount': lto_deduction_tax.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP),       # Less Tax = ₱3,465.40  
        'expected_commission': lto_deduction_net.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)  # Total Due = ₱19,637.28 (after tax)
    }


def _consolidate_billing_history(all_received_tranches):
    """
    Consolidate billing history to show only one row total.
    Sums all receivable amounts and percentages into a single entry.
    Shows the most recent date from all receivables.
    """
    if not all_received_tranches:
        return []
    
    # Sum all amounts and percentages into a single consolidated entry
    total_amount = Decimal('0.00')
    total_percentage = Decimal('0.00')
    latest_date = None
    
    for tranche in all_received_tranches:
        # Sum the amounts
        if tranche.received_amount:
            total_amount += tranche.received_amount
        
        # Track the latest date
        if tranche.date_received:
            if latest_date is None or tranche.date_received > latest_date:
                latest_date = tranche.date_received
        
        # Calculate percentage for this tranche using actual record percentages
        if tranche.tranche_record:
            record = tranche.tranche_record
            same_type_tranches = record.payments.filter(is_lto=tranche.is_lto)
            same_type_total = same_type_tranches.aggregate(total=Sum('expected_amount'))['total'] or Decimal('1.0')
            
            # Use actual option1_percentage or option2_percentage from the record
            period_percentage = record.option2_percentage if tranche.is_lto else record.option1_percentage
            percentage_within_type = (tranche.expected_amount / same_type_total) * period_percentage
            total_percentage += percentage_within_type
    
    # Return single consolidated entry
    return [{
        'date_received': latest_date,
        'amount': total_amount,
        'status': 'Received',
        'percentage': total_percentage,
        'due_date': latest_date,  # Use latest date as due date
    }]


def _get_tranche_data_for_invoice(tranche_payment):
    """Get the exact tranche data as displayed in view_tranche schedule tables."""
    record = tranche_payment.tranche_record
    
    if tranche_payment.is_lto:
        # LTO calculation - use the pre-calculated data from view logic (same as DP)
        lto_data = _get_lto_tranche_data_from_view_logic(record)
        
        return {
            'net_amount': lto_data['net_amount'],
            'tax_amount': lto_data['tax_amount'],
            'expected_commission': lto_data['expected_commission']
        }
    else:
        # DP calculation - use the pre-calculated data from view logic
        dp_data = _get_dp_tranche_data_from_view_logic(record)
        
        return {
            'net_amount': dp_data['net_amount'],
            'tax_amount': dp_data['tax_amount'],
            'expected_commission': dp_data['expected_commission']
        }


def _get_invoice_context(invoice, request):
    """Generate the context dictionary for an invoice view."""
    # Auto-populate Bill To data from developer if not already set
    if invoice.tranche and invoice.tranche.tranche_record:
        project_name = invoice.tranche.tranche_record.project_name
        try:
            from .models import Property, Developer
            property_obj = Property.objects.filter(name=project_name).first()
            if property_obj and property_obj.developer:
                developer = property_obj.developer
                # Only update if client data is empty or default
                if not invoice.client_name or invoice.client_name == "Client Name":
                    invoice.client_name = developer.name
                if not invoice.client_address or invoice.client_address == "Client Address":
                    invoice.client_address = developer.address or ""
                if not invoice.client_tin or invoice.client_tin == "Client TIN":
                    invoice.client_tin = developer.tin_number or ""
                invoice.save()
        except Exception as e:
            print(f"Warning: Could not auto-populate developer data: {e}")
    
    # Check if this is a combined invoice (qty > 1 indicates multiple tranches)
    is_combined_invoice = invoice.qty > 1
    combined_tranches = []
    
    # Initialize variables that are used throughout the function
    is_lto_invoice = False
    lto_tranches = []
    
    if is_combined_invoice:
        # Extract tranche IDs from the notes field
        if invoice.notes and "Combined invoice for tranches:" in invoice.notes:
            try:
                tranche_ids_str = invoice.notes.split("Combined invoice for tranches:")[1].strip()
                tranche_ids = [int(id.strip()) for id in tranche_ids_str.split(',')]
                combined_tranches = list(TranchePayment.objects.filter(id__in=tranche_ids).select_related('tranche_record'))
            except (ValueError, IndexError):
                # Fallback to single tranche if parsing fails
                combined_tranches = [invoice.tranche] if invoice.tranche else []
        
        # Calculate amounts based on Expected Commission from tranche view table
        if combined_tranches:
            # Calculate totals from the actual tranche expected amounts (Expected Commission column)
            total_expected_commission = sum(tranche.expected_amount for tranche in combined_tranches)
            
            # Calculate net commission before tax for all tranches
            total_net_commission = Decimal('0.00')
            total_tax_amount = Decimal('0.00')
            
            for tranche in combined_tranches:
                # Get exact tranche data as calculated in view_tranche
                tranche_data = _get_tranche_data_for_invoice(tranche)
                
                total_net_commission += tranche_data['net_amount']
                total_tax_amount += tranche_data['tax_amount']
            
            net_price = total_net_commission.quantize(Decimal("0.01"))
            vat_amount = total_tax_amount.quantize(Decimal("0.01"))
            subtotal = total_expected_commission.quantize(Decimal("0.01"))
            qty = invoice.qty
            amount_net_vat = net_price
            
            # Calculate individual breakdown for display purposes only
            # This is for showing individual tranche details, but doesn't affect totals
            individual_net_commissions = []
            individual_tax_amounts = []
            
            # Calculate proportional breakdown based on stored totals
            total_expected = sum(tranche.expected_amount for tranche in combined_tranches)
            if total_expected > 0:
                for tranche in combined_tranches:
                    # Calculate proportional share of the stored commission
                    proportion = tranche.expected_amount / total_expected
                    tranche_net_commission = (net_price * proportion).quantize(Decimal('0.01'))
                    tranche_tax_amount = (vat_amount * proportion).quantize(Decimal('0.01'))
                    
                    individual_net_commissions.append(tranche_net_commission)
                    individual_tax_amounts.append(tranche_tax_amount)
            else:
                # Fallback if no expected amounts
                individual_net_commissions = [net_price / len(combined_tranches)] * len(combined_tranches)
                individual_tax_amounts = [vat_amount / len(combined_tranches)] * len(combined_tranches)
            
            # Store individual commission breakdown for template
            combined_commission_breakdown = list(zip(combined_tranches, individual_net_commissions, individual_tax_amounts))
            
            print(f"DEBUG: Combined invoice using stored values - net_price: {net_price}, vat_amount: {vat_amount}, subtotal: {subtotal}")
        else:
            # Fallback to invoice values if no combined tranches found
            net_price = invoice.unit_price
            vat_amount = (net_price * (invoice.vat_rate / Decimal("100"))).quantize(Decimal("0.01"))
            subtotal = (net_price - vat_amount).quantize(Decimal("0.01"))
            qty = invoice.qty
            amount_net_vat = net_price
            combined_commission_breakdown = []
            
            print(f"DEBUG: Combined invoice fallback using stored values - net_price: {net_price}, vat_amount: {vat_amount}, subtotal: {subtotal}")
    else:
        # Single tranche invoice
        tranche = invoice.tranche
        if invoice.tranche and invoice.tranche.tranche_record:
            # Get exact tranche data as calculated in view_tranche
            tranche_data = _get_tranche_data_for_invoice(tranche)
            
            # For LTO: net_amount is the commission before tax (₱23,102.68)
            # For DP: net_amount is the commission before tax 
            net_price = tranche_data['net_amount']      # Commission (before tax)
            vat_amount = tranche_data['tax_amount']     # Less Tax
            subtotal = tranche_data['expected_commission']  # Total Due (after tax)
            
            qty = invoice.qty
            amount_net_vat = net_price
            combined_commission_breakdown = []
            
        # --- Check if this is a Loan Take Out invoice and override with LTO data ---
        
        if invoice.tranche and invoice.tranche.tranche_record and invoice.tranche.is_lto:
            record = invoice.tranche.tranche_record
            is_lto_invoice = True
            
            # Get LTO tranche data
            lto_payment = record.payments.filter(is_lto=True).first()
            if lto_payment:
                # Calculate LTO values (similar to view_tranche logic)
                vat_rate_decimal = record.vat_rate / Decimal(100)
                net_of_vat_base = record.total_contract_price / (Decimal(1) + vat_rate_decimal)
                less_process_fee = (record.total_contract_price * record.process_fee_percentage) / Decimal(100)
                total_selling_price = net_of_vat_base - less_process_fee
                gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
                net_of_vat = gross_commission / (Decimal(1) + vat_rate_decimal)
                net_commission = gross_commission - (net_of_vat * (record.withholding_tax_rate / Decimal(100)))
                
                # Calculate LTO values
                option2_value = net_commission * (record.option2_percentage / Decimal(100))
                option2_tax_rate = record.option2_tax_rate / Decimal(100)
                lto_deduction_value = option2_value
                lto_deduction_tax = lto_deduction_value * option2_tax_rate
                lto_deduction_net = lto_deduction_value - lto_deduction_tax
                lto_expected_commission = lto_deduction_net.quantize(Decimal('0.01'))
                
                # Override invoice table data with LTO-specific values
                net_price = lto_deduction_value  # Net Commission (before tax)
                vat_amount = lto_deduction_tax   # Less Tax
                subtotal = lto_expected_commission  # Expected Commission (after tax)
                amount_net_vat = lto_deduction_value
                
                lto_tranches.append({
                    'tranche': lto_payment,
                    'tax_amount': lto_deduction_tax,
                    'net_amount': lto_deduction_net,
                    'expected_commission': lto_expected_commission,
                    'balance': lto_expected_commission - lto_payment.received_amount,
                    'initial_balance': lto_payment.initial_balance
                })
        else:
            # Fallback to stored values if no tranche data
            qty = invoice.qty
            net_price = invoice.unit_price
            vat_amount = (net_price * (invoice.vat_rate / Decimal("100"))).quantize(Decimal("0.01"))
            subtotal = (net_price - vat_amount).quantize(Decimal("0.01"))
            amount_net_vat = net_price
            combined_commission_breakdown = []

    # Default values for summary
    summary_gross_commission = Decimal('0.00')
    summary_net_of_vat = Decimal('0.00')
    summary_withholding_tax_amount = Decimal('0.00')
    summary_net_commission = Decimal('0.00')
    summary_vat_rate = Decimal('0.00')
    summary_vat_amount = Decimal('0.00')
    summary_withholding_tax_rate = Decimal('0.00')

    # Use the updated two-path calculation logic for the summary section
    if invoice.tranche and invoice.tranche.tranche_record:
        record = invoice.tranche.tranche_record

        # Use the new two-path calculation logic that matches views.py
        if record.net_of_vat_amount and record.net_of_vat_amount > 0:
            # Path 1: Use Net of VAT divisor calculation
            net_of_vat_base = record.total_contract_price / record.net_of_vat_amount
            less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
            total_selling_price = net_of_vat_base - less_process_fee
            summary_gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
        else:
            # Path 2: Use Total Contract Price directly when Net of VAT is 0 or empty
            net_of_vat_base = record.total_contract_price
            less_process_fee = record.total_contract_price * (record.process_fee_percentage / Decimal(100))
            total_selling_price = record.total_contract_price - less_process_fee
            summary_gross_commission = record.total_contract_price * (record.commission_rate / Decimal(100))

        # Common calculations for both paths
        summary_vat_rate = record.vat_rate
        vat_rate_decimal = record.vat_rate / Decimal(100)
        
        # Calculate VAT and Net of VAT from gross commission
        summary_vat_amount = summary_gross_commission * vat_rate_decimal
        summary_net_of_vat = summary_gross_commission - summary_vat_amount
        
        # Withholding tax calculations
        summary_withholding_tax_rate = record.withholding_tax_rate
        withholding_tax_rate_decimal = summary_withholding_tax_rate / Decimal(100)
        summary_withholding_tax_amount = summary_net_of_vat * withholding_tax_rate_decimal
        
        # Final net commission
        summary_net_commission = summary_net_of_vat - summary_withholding_tax_amount

    # --- Prepare Billing Statement Data ---
    billing_statement_items = []
    current_billing_item = {}

    if is_combined_invoice and combined_tranches:
        # For combined invoices, use all combined tranches
        record = combined_tranches[0].tranche_record
        all_tranches = record.payments.all().order_by('expected_date')
        
        # Calculate the total expected commission for the entire record
        total_expected_commission = record.payments.aggregate(total=Sum('expected_amount'))['total'] or Decimal('1.0')
        if total_expected_commission == 0:
            total_expected_commission = Decimal('1.0')

        # Create combined billing item for current invoice
        combined_expected_amount = sum(t.expected_amount for t in combined_tranches)
        combined_received_amount = sum(t.received_amount or Decimal('0') for t in combined_tranches)
        
        # Calculate percentage based on period type (DP or LTO should each be 50%)
        # Check if all combined tranches are of the same type
        is_all_lto = all(t.is_lto for t in combined_tranches)
        is_all_dp = all(not t.is_lto for t in combined_tranches)
        
        if is_all_lto or is_all_dp:
            # All tranches are of the same type, use actual percentage from record
            record = combined_tranches[0].tranche_record
            combined_percentage = record.option2_percentage if is_all_lto else record.option1_percentage
        else:
            # Mixed types, calculate based on total expected commission
            combined_percentage = (combined_expected_amount / total_expected_commission) * Decimal('100')
        
        current_billing_item = {
            'date_received': min(t.date_received for t in combined_tranches if t.date_received) if any(t.date_received for t in combined_tranches) else None,
            'amount': combined_received_amount,
            'status': 'Received' if all(t.status == 'Received' for t in combined_tranches) else 'Pending',
            'percentage': combined_percentage,
            'due_date': min(t.expected_date for t in combined_tranches),
        }

        # Collect all received tranches for consolidation
        all_received_tranches = [t for t in all_tranches if t.status == 'Received']
        
    elif invoice.tranche and invoice.tranche.tranche_record:
        # Single tranche invoice logic
        record = invoice.tranche.tranche_record
        all_tranches = record.payments.all().order_by('expected_date')
        
        # Calculate the total expected commission for the entire record to be used as the base for percentage calculation
        total_expected_commission = record.payments.aggregate(total=Sum('expected_amount'))['total'] or Decimal('1.0')
        if total_expected_commission == 0:
            total_expected_commission = Decimal('1.0') # Avoid division by zero

        for tranche_payment in all_tranches:
            # Calculate percentage based on period type (DP or LTO should each be 50%)
            # Get all tranches of the same type (DP or LTO) for this record
            same_type_tranches = record.payments.filter(is_lto=tranche_payment.is_lto)
            same_type_total = same_type_tranches.aggregate(total=Sum('expected_amount'))['total'] or Decimal('1.0')
            
            # Calculate percentage within the period type using actual record percentages
            period_percentage = record.option2_percentage if tranche_payment.is_lto else record.option1_percentage
            percentage_within_type = (tranche_payment.expected_amount / same_type_total) * period_percentage
            
            item_data = {
                'date_received': tranche_payment.date_received,
                'amount': tranche_payment.received_amount,
                'status': tranche_payment.status,
                'percentage': percentage_within_type,
                'due_date': tranche_payment.expected_date,
            }

            # If this is the tranche for the current invoice, store its data separately
            if invoice.tranche and invoice.tranche.pk == tranche_payment.pk:
                current_billing_item = item_data

        # Collect all received tranches for consolidation
        all_received_tranches = [t for t in all_tranches if t.status == 'Received']
    else:
        all_received_tranches = []

    # Consolidate billing history: Group by invoice and sum amounts
    billing_statement_items = _consolidate_billing_history(all_received_tranches)

    # Check for previously released commissions for the same deal (TrancheRecord)
    previous_invoices = []
    if invoice.tranche and invoice.tranche.tranche_record:
        record = invoice.tranche.tranche_record
        # Find all other received payments for this record
        other_payments = record.payments.filter(status='Received').exclude(pk=invoice.tranche.pk).order_by('-date_received')

        total_expected_commission_for_record = record.payments.aggregate(total=Sum('expected_amount'))['total'] or Decimal('1.0')

        for payment in other_payments:
            # Find the invoice associated with that payment
            prev_invoice = payment.invoices.first()
            if prev_invoice:
                # Calculate percentage based on period type using actual record percentages
                same_type_tranches = record.payments.filter(is_lto=payment.is_lto)
                same_type_total = same_type_tranches.aggregate(total=Sum('expected_amount'))['total'] or Decimal('1.0')
                period_percentage = record.option2_percentage if payment.is_lto else record.option1_percentage
                percentage = (payment.expected_amount / same_type_total) * period_percentage if same_type_total else 0
                
                previous_invoices.append({
                    'tranche_name': f"Tranche-{record.id}",  # Use the record ID for a consistent name
                    'release_date': payment.date_received,
                    'amount': payment.received_amount,
                    'percentage': percentage,
                    'invoice_no': prev_invoice.invoice_no,
                })

    # Calculate totals
    total_due = subtotal
    
    # Add LTO template variables for direct access
    lto_deduction_value = Decimal('0.00')
    lto_deduction_tax = Decimal('0.00') 
    lto_deduction_net = Decimal('0.00')
    
    if is_lto_invoice and invoice.tranche and invoice.tranche.tranche_record:
        tranche_data = _get_tranche_data_for_invoice(invoice.tranche)
        lto_deduction_value = tranche_data['net_amount']
        lto_deduction_tax = tranche_data['tax_amount']
        lto_deduction_net = tranche_data['expected_commission']
    
    context = {
        "invoice": invoice,
        "qty": qty,
        "net_price": net_price,
        "vat_amount": vat_amount,
        "subtotal": subtotal,
        "total_due": total_due,
        "amount_net_vat": amount_net_vat,
        "is_combined_invoice": is_combined_invoice,
        "combined_tranches": combined_tranches,
        "combined_commission_breakdown": combined_commission_breakdown,
        "summary_gross_commission": summary_gross_commission,
        "summary_net_of_vat": summary_net_of_vat,
        "summary_withholding_tax_amount": summary_withholding_tax_amount,
        "summary_net_commission": summary_net_commission,
        "summary_vat_rate": summary_vat_rate,
        "summary_vat_amount": summary_vat_amount,
        "summary_withholding_tax_rate": summary_withholding_tax_rate,
        "lto_tranches": lto_tranches,
        "is_lto_invoice": is_lto_invoice,
        "lto_deduction_value": lto_deduction_value,
        "lto_deduction_tax": lto_deduction_tax,
        "lto_deduction_net": lto_deduction_net,
        "billing_statement_items": billing_statement_items,
        "current_billing_item": current_billing_item,
    }
    
    # Permissions
    can_edit_bill_to = request.user.is_staff
    can_check = request.user.is_staff
    can_approve = request.user.is_superuser
    can_prepare = request.user == invoice.prepared_by
    
    # Add signature URLs (uploaded or default)
    signature_urls = {
        'prepared_by_signature_url': _get_signature_url_or_default(invoice, 'prepared_by'),
        'checked_by_signature_url': _get_signature_url_or_default(invoice, 'checked_by'),
        'approved_by_signature_url': _get_signature_url_or_default(invoice, 'approved_by'),
    }
    
    # Add signature dates for consistent display
    signature_dates = {
        'prepared_by_display_date': invoice.prepared_by_date or invoice.created_at,
        'checked_by_display_date': invoice.checked_by_date or invoice.created_at,
        'approved_by_display_date': invoice.approved_by_date or invoice.created_at,
    }
    
    context.update({
        'can_edit_bill_to': can_edit_bill_to,
        'can_check': can_check,
        'can_approve': can_approve,
        'can_prepare': can_prepare,
        **signature_urls,
        **signature_dates,
    })
    
    # Extract stored item data from notes field
    stored_items = []
    if invoice.notes:
        import json
        for line in invoice.notes.split('\n'):
            if line.startswith('Items Data:'):
                try:
                    items_json = line.replace('Items Data:', '').strip()
                    stored_items = json.loads(items_json)
                    break
                except (json.JSONDecodeError, ValueError):
                    pass

    # Get buyer name and unit ID from tranche record for all cases
    buyer_name = ""
    unit_id = ""
    if invoice.tranche and invoice.tranche.tranche_record:
        buyer_name = invoice.tranche.tranche_record.buyer_name or ""
        unit_id = invoice.tranche.tranche_record.unit_id or ""
        print(f"DEBUG: Single invoice - buyer_name: '{buyer_name}', unit_id: '{unit_id}'")
    elif is_combined_invoice and combined_tranches:
        # For combined invoices, use the first tranche's data
        buyer_name = combined_tranches[0].tranche_record.buyer_name or ""
        unit_id = combined_tranches[0].tranche_record.unit_id or ""
        print(f"DEBUG: Combined invoice - buyer_name: '{buyer_name}', unit_id: '{unit_id}'")

    # Add buyer_name and unit_id to existing stored_items if they don't have them
    if stored_items:
        for item in stored_items:
            if 'buyer_name' not in item:
                item['buyer_name'] = buyer_name
            if 'unit_id' not in item:
                item['unit_id'] = unit_id

    # If no stored items, create default item data
    if not stored_items:
        # For LTO invoices, the line item amount should be the total due (lto_deduction_net)
        # For DP invoices, it should be the subtotal (which is also the total due)
        line_item_amount = lto_deduction_net if is_lto_invoice else subtotal

        stored_items = [{
            'item_code': 'COMBINED DPC' if is_combined_invoice else ('LTO' if is_lto_invoice else 'DPC'),
            'description': f"Commission for {invoice.due_date.strftime('%B %Y') if invoice.due_date else ''}",
            'quantity': invoice.qty,
            'amount': float(line_item_amount),
            'due_date': current_billing_item.get('due_date').strftime('%Y-%m-%d') if current_billing_item and current_billing_item.get('due_date') else '',
            'status': current_billing_item.get('status', 'Pending') if current_billing_item else 'Pending',
            'percentage': float(current_billing_item.get('percentage', 0)) if current_billing_item and current_billing_item.get('percentage') else 0.0,
            'buyer_name': buyer_name,
            'unit_id': unit_id
        }]

    context['stored_items'] = stored_items
    
    # Extract payment terms from notes field
    context['payment_terms'] = _extract_payment_terms_from_notes(invoice)

    return context


def invoice_view(request, invoice_id):
    """Render a printable invoice page for the given BillingInvoice."""
    invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
    context = _get_invoice_context(invoice, request)    
    return render(request, 'invoice.html', context)


@login_required
@require_POST
def sign_invoice(request, invoice_id, role):
    invoice = get_object_or_404(BillingInvoice, id=invoice_id)

    if role == 'checked_by' and request.user.is_staff and not invoice.checked_by:
        invoice.checked_by = request.user
        invoice.checked_by_date = now()
        invoice.save()
        messages.success(request, 'Invoice successfully marked as checked.')
    elif role == 'approved_by' and request.user.is_superuser and not invoice.approved_by:
        invoice.approved_by = request.user
        invoice.approved_by_date = now()
        invoice.save()
        messages.success(request, 'Invoice successfully marked as approved.')
    else:
        messages.error(request, 'You do not have permission to perform this action or it has already been signed.')

    return redirect('invoice_view', invoice_id=invoice.id)


@login_required
def upload_signature(request, invoice_id, role):
    invoice = get_object_or_404(BillingInvoice, id=invoice_id)
    
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid request method.'}, status=405)
    
    # Get action from form data (role comes from URL parameter)
    action = request.POST.get('action', 'upload')
    
    
    if not role or role not in ['prepared_by', 'checked_by', 'approved_by']:
        return JsonResponse({'success': False, 'error': 'Invalid role specified.'}, status=400)

    # Permission checks
    if role == 'prepared_by' and request.user != invoice.prepared_by:
        return JsonResponse({'success': False, 'error': 'You do not have permission to sign as prepared by.'}, status=403)
    if role == 'checked_by' and not request.user.is_staff:
        return JsonResponse({'success': False, 'error': 'You do not have permission to sign as checked by.'}, status=403)
    if role == 'approved_by' and not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'You do not have permission to sign as approved by.'}, status=403)

    if action == 'clear':
        # Clear only the specific signature
        sig_field_name = f"{role}_signature"
        sig_field = getattr(invoice, sig_field_name, None)
        if sig_field and sig_field.name and os.path.exists(sig_field.path):
            os.remove(sig_field.path)
        setattr(invoice, sig_field_name, None)
        
        # Clear related date fields
        if role == 'prepared_by':
            invoice.prepared_by_date = None
        elif role == 'checked_by':
            invoice.checked_by = None
            invoice.checked_by_date = None
        elif role == 'approved_by':
            invoice.approved_by = None
            invoice.approved_by_date = None
            
        invoice.save()
        return JsonResponse({'success': True, 'message': f'{role.replace("_", " ").title()} signature cleared.'})

    elif action == 'upload' and ('signature' in request.FILES or 'signature_image' in request.FILES):
        signature_image = request.FILES.get('signature') or request.FILES.get('signature_image')

        # Delete only the old signature for this role
        sig_field_name = f"{role}_signature"
        sig_field = getattr(invoice, sig_field_name, None)
        if sig_field and sig_field.name and os.path.exists(sig_field.path):
            os.remove(sig_field.path)

        # Save the new signature to the specific role field only
        setattr(invoice, sig_field_name, signature_image)

        # Update date fields and user fields based on the specific role
        if role == 'prepared_by':
            invoice.prepared_by_date = now()
        elif role == 'checked_by':
            invoice.checked_by = request.user
            invoice.checked_by_date = now()
        elif role == 'approved_by':
            invoice.approved_by = request.user
            invoice.approved_by_date = now()

        # Save only the specific fields to avoid affecting other signature fields
        update_fields = [sig_field_name]
        if role == 'prepared_by':
            update_fields.append('prepared_by_date')
        elif role == 'checked_by':
            update_fields.extend(['checked_by', 'checked_by_date'])
        elif role == 'approved_by':
            update_fields.extend(['approved_by', 'approved_by_date'])
            
        invoice.save(update_fields=update_fields)

        # Refresh to get the new URL
        invoice.refresh_from_db()
        
        signature_field = getattr(invoice, sig_field_name)
        signature_url = signature_field.url if signature_field else ''
        
        return JsonResponse({
            'success': True,
            'message': f'{role.replace("_", " ").title()} signature uploaded successfully.',
            'signature_url': signature_url
        })

    else:
        return JsonResponse({
            'success': False, 
            'error': f'Invalid action or missing file. Action: {action}, Files: {list(request.FILES.keys())}'
        }, status=400)


@login_required
def invoice_pdf(request, invoice_id):
    """Generate pixel-perfect PDF that exactly replicates the invoice.html template."""
    try:
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
        import os
        
        # Get invoice and context
        invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
        context = _get_invoice_context(invoice, request)
        
        # Set up paths for assets
        static_dir = os.path.join(settings.BASE_DIR, 'sparc', 'static')
        logo_path = os.path.join(static_dir, 'media', 'LOGO.png')
        
        # Add PDF-specific context to show logo properly
        context.update({
            'is_pdf_generation': True,
            'logo_path': f'file:///{logo_path.replace(chr(92), "/")}' if os.path.exists(logo_path) else None,
        })
        
        print(f"Generating pixel-perfect PDF for invoice {invoice.invoice_no}")
        
        # Render the complete HTML template
        html_string = render_to_string("invoice.html", context, request=request)
        print("HTML template rendered successfully")
        
        # Clean HTML and embed Tailwind CSS directly
        complete_html = _prepare_html_with_tailwind(html_string, logo_path)
        print("HTML processed with embedded Tailwind CSS")
        
        # Configure fonts for better rendering
        font_config = FontConfiguration()
        
        # Generate PDF with full CSS support
        html_doc = HTML(
            string=complete_html,
            base_url=request.build_absolute_uri('/'),
            encoding='utf-8'
        )
        
        # Create CSS for print optimization with maximum page utilization
        print_css = CSS(string="""
            @page {
                size: A4;
                margin: 0.1in;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            
            html {
                zoom: 0.85;
                transform: scale(0.85);
                transform-origin: top center;
            }
            
            body {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
                color-adjust: exact !important;
                font-size: 0.95em !important;
                line-height: 1.3 !important;
                margin: 0 auto !important;
                max-width: 100% !important;
            }
            
            * {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
                color-adjust: exact !important;
            }
            
            .no-print {
                display: none !important;
            }
            
            /* Maximize content and use full width */
            .max-w-4xl {
                max-width: 98% !important;
                margin: 0 auto !important;
                padding: 0.4rem !important;
            }
            
            .my-10 {
                margin-top: 0.4rem !important;
                margin-bottom: 0.4rem !important;
            }
            
            .p-8 {
                padding: 0.8rem !important;
            }
            
            .pb-6 {
                padding-bottom: 0.5rem !important;
            }
            
            .mt-6, .mb-8 {
                margin-top: 0.5rem !important;
                margin-bottom: 0.5rem !important;
            }
            
            .space-y-8 > * + * {
                margin-top: 0.7rem !important;
            }
            
            .pt-6 {
                padding-top: 0.5rem !important;
            }
            
            .mt-8 {
                margin-top: 0.7rem !important;
            }
            
            /* Balanced table spacing */
            .p-3 {
                padding: 0.4rem !important;
            }
            
            .p-4 {
                padding: 0.5rem !important;
            }
            
            .p-2 {
                padding: 0.3rem !important;
            }
            
            /* Balanced header */
            header {
                padding-bottom: 0.5rem !important;
                margin-bottom: 0.5rem !important;
            }
            
            /* Balanced footer and signatures */
            footer {
                margin-top: 0.5rem !important;
                padding-top: 0.4rem !important;
                font-size: 0.8em !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }
            
            .signature-container {
                margin-bottom: 0.2rem !important;
            }
            
            .signature-container img {
                height: 3rem !important;
                margin-bottom: 0.4rem !important;
            }
            
            .grid-cols-3 {
                gap: 0.7rem !important;
            }
            
            /* Balanced sections */
            section {
                margin-bottom: 0.6rem !important;
            }
            
            /* Ensure all colors and backgrounds render */
            .bg-blue-600 {
                background-color: #2563eb !important;
                color: white !important;
            }
            
            .bg-gray-50 {
                background-color: #f9fafb !important;
            }
            
            .text-blue-600 {
                color: #2563eb !important;
            }
            
            .border-gray-200 {
                border-color: #e5e7eb !important;
            }
            
            .shadow-2xl {
                box-shadow: 0 5px 15px -3px rgba(0, 0, 0, 0.1) !important;
            }
            
            /* Compact text sizes */
            .text-xs {
                font-size: 0.65rem !important;
            }
            
            .text-sm {
                font-size: 0.75rem !important;
            }
            
            /* Remove excessive spacing */
            .border-t-2 {
                margin-top: 0.3rem !important;
                padding-top: 0.3rem !important;
            }
            
            /* Hide WeasyPrint metadata and identifiers */
            [data-weasyprint-pdf-id],
            [data-pdf-id],
            .weasyprint-metadata,
            .pdf-metadata,
            *[id*="weasyprint"],
            *[class*="weasyprint"],
            *[id*="pdf-id"],
            *[class*="pdf-id"] {
                display: none !important;
                visibility: hidden !important;
                opacity: 0 !important;
                position: absolute !important;
                left: -9999px !important;
            }
            
            /* Hide any text nodes that look like random identifiers */
            body::after,
            html::after,
            *::after,
            *::before {
                content: none !important;
            }
            
            /* Hide elements containing alphanumeric strings that look like IDs */
            *:contains("4VffNnl64HmtWWbt0A5geD0QnJcv1SQwsWh"),
            *:contains("0OgQyJa2FbZX3f67raOlD079EuZraAlhoPmdvhb") {
                display: none !important;
                visibility: hidden !important;
            }
            
            /* Hide any standalone text elements at the bottom */
            body > *:last-child:not(div):not(section):not(footer),
            body > div:last-child > *:last-child:only-child {
                display: none !important;
            }
            
            /* Ensure footer stays on first page */
            .max-w-4xl {
                position: relative !important;
                min-height: calc(100vh - 2rem) !important;
            }
            
            footer {
                position: relative !important;
                margin-top: auto !important;
            }
            
            /* Add company footer at bottom */
            @page {
                @bottom-center {
                    content: "© Inner SPARC Realty Corporation";
                    font-size: 9px;
                    color: #666;
                    margin-top: 5px;
                }
            }
            
            /* Force all content to stay on one page */
            * {
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }
            
            body, html {
                height: auto !important;
                overflow: visible !important;
            }
        """)
        
        # Try to disable all WeasyPrint metadata generation
        pdf_file = html_doc.write_pdf(
            stylesheets=[print_css],
            font_config=font_config,
            optimize_images=True,
            pdf_identifier=False,
            pdf_version='1.4',
            pdf_forms=False
        )
        
        print(f"Pixel-perfect PDF generated successfully: {len(pdf_file)} bytes")
        
        # Create response
        response = HttpResponse(pdf_file, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="invoice_{invoice.invoice_no}.pdf"'
        
        return response
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"PDF Generation Error: {str(e)}")
        print(f"Full traceback: {error_details}")
        return HttpResponse(f"Error generating PDF: {str(e)}", status=500)


@login_required
def email_invoice(request, invoice_id):
    """Generate a static PNG image of the complete invoice and send as email attachment."""
    if request.method == 'POST':
        print("\n--- [EMAIL INVOICE PROCESS STARTED] ---")
        invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
        recipient_email = request.POST.get('email')

        if not recipient_email:
            print("[ERROR] No recipient email provided.")
            return JsonResponse({'status': 'error', 'message': 'Email address not provided.'}, status=400)

        print(f"Step 1: Preparing to email invoice {invoice.invoice_no} to {recipient_email}")

        # Generate the complete invoice context with all data
        context = _get_invoice_context(invoice, request)
        html_body = render_to_string("invoice.html", context)

        # Make the HTML self-contained with absolute paths and embedded CSS
        final_html = _make_html_self_contained(html_body, request)



        subject = f"Invoice {invoice.invoice_no} from {getattr(settings, 'COMPANY_NAME', 'Inner Sparc Realty Services')}"
        
        text_body = f"""Dear Valued Client,\n\nPlease find attached your invoice #{invoice.invoice_no}.\n\nThank you for your business!\n\nBest regards,\nInner Sparc Realty Services"""
        
        email = EmailMessage(
            subject,
            body=text_body,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@innersparc.com'),
            to=[recipient_email],
        )
        
        print("Step 2: Generating invoice image...")
        image_data = _generate_invoice_image(final_html, invoice.invoice_no)

        json_status = 'error'
        message = ''

        if image_data:
            print(f"Step 3: Image generation SUCCEEDED. Size: {len(image_data)} bytes.")
            email.attach(
                f'Invoice_{invoice.invoice_no}.png',
                image_data,
                'image/png'
            )
            message = f"Invoice {invoice.invoice_no} with image attachment sent to {recipient_email}."
            json_status = 'success'
        else:
            print("Step 3: Image generation FAILED. Email will be sent with text body only.")
            message = f"Invoice {invoice.invoice_no} sent to {recipient_email}, but image generation failed. Please check server logs."
            json_status = 'warning'

        try:
            print("Step 4: Attempting to send email...")
            email.send()
            print("Step 5: Email sent SUCCESSFULLY.")
            if json_status == 'success':
                messages.success(request, message)
            else:
                messages.warning(request, message)
            return JsonResponse({'status': json_status, 'message': message})
        except Exception as e:
            error_message = f'An error occurred while sending the email: {e}'
            print(f"Step 5: Email sending FAILED. Error: {e}")
            messages.error(request, error_message)
            return JsonResponse({'status': 'error', 'message': error_message}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)


def _make_html_self_contained(html_content, request):
    """
    Parses HTML, converts all static resource URLs to absolute paths,
    and injects the main CSS file to ensure proper rendering in wkhtmltoimage.
    """
    print("--- Making HTML self-contained for image generation ---")
    soup = BeautifulSoup(html_content, "html.parser")
    base_url = request.build_absolute_uri('/')

    # Convert all image and script URLs to absolute paths
    for tag in soup.find_all(['img', 'script']):
        if tag.get('src'):
            absolute_url = urljoin(base_url, tag['src'].lstrip('/'))
            tag['src'] = absolute_url
            print(f"Converted resource URL: {absolute_url}")

    # Remove existing stylesheet links to prevent conflicts
    for tag in soup.find_all('link', rel="stylesheet"):
        tag.decompose()

    # Inject the main CSS file directly into the head
    try:
        css_path = os.path.join(settings.BASE_DIR, 'static', 'css', 'dist', 'styles.css')
        with open(css_path, 'r', encoding='utf-8') as f:
            css_string = f.read()
        
        style_tag = soup.new_tag('style')
        style_tag.string = css_string
        
        if soup.head:
            soup.head.append(style_tag)
            print("CSS styles successfully injected into HTML head.")
        else:
            print("[WARNING] No <head> tag found to inject CSS into.")

    except FileNotFoundError:
        print("[WARNING] styles.css not found. The generated image may be unstyled.")
    except Exception as e:
        print(f"[WARNING] An error occurred while injecting CSS: {e}")

    return str(soup)


def invoice_csv(request, invoice_id):
    """Return invoice data as CSV so Excel can open it."""
    import csv
    from django.http import HttpResponse

    invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
    data = _compute(invoice)

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="invoice_{invoice.invoice_no}.csv"'

    writer = csv.writer(response)
    writer.writerow(["Invoice No", invoice.invoice_no])
    writer.writerow(["Issue Date", invoice.issue_date])
    writer.writerow(["Due Date", invoice.due_date])
    writer.writerow([])

    writer.writerow(["Item Code", "Description", "Quantity", "Net Commission", "Less Tax", "Expected Commission"])
    writer.writerow([
        "SC",
        f"Seller's Commission – {invoice.due_date.strftime('%B %Y')}",
        invoice.qty,
        f"{data['net_price']}",
        f"{data['vat_amount']}",
        f"{data['subtotal']}",
    ])

    writer.writerow([])
    writer.writerow(["TOTAL DUE", data['subtotal']])

    return response


@login_required
def update_bill_to(request, invoice_id):
    if request.method == 'POST':
        invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
        invoice.client_name = request.POST.get('client_name', invoice.client_name)
        invoice.client_address = request.POST.get('client_address', invoice.client_address)
        invoice.client_tin = request.POST.get('client_tin', invoice.client_tin)
        invoice.save()
        messages.success(request, 'Billing information updated successfully.')
        return redirect('invoice_view', invoice_id=invoice.id)
    
    # Redirect to the invoice detail page if the request is not POST
    return redirect('invoice_view', invoice_id=invoice_id)


@login_required
def update_billing_details(request, invoice_id):
    """Update billing details including dates, reference, and terms."""
    if request.method == 'POST':
        invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
        
        # Update billing details
        issue_date = request.POST.get('issue_date')
        due_date = request.POST.get('due_date')
        reference_no = request.POST.get('reference_no')
        payment_terms = request.POST.get('payment_terms')
        
        if issue_date:
            from datetime import datetime
            invoice.issue_date = datetime.strptime(issue_date, '%Y-%m-%d').date()
        
        if due_date:
            from datetime import datetime
            invoice.due_date = datetime.strptime(due_date, '%Y-%m-%d').date()
        
        if reference_no:
            invoice.reference_no = reference_no
        
        # Store payment terms in notes field if not already stored
        if payment_terms:
            if invoice.notes:
                # Check if payment terms are already in notes
                if 'Payment Terms:' not in invoice.notes:
                    invoice.notes += f"\nPayment Terms: {payment_terms}"
                else:
                    # Update existing payment terms
                    lines = invoice.notes.split('\n')
                    updated_lines = []
                    for line in lines:
                        if line.startswith('Payment Terms:'):
                            updated_lines.append(f'Payment Terms: {payment_terms}')
                        else:
                            updated_lines.append(line)
                    invoice.notes = '\n'.join(updated_lines)
            else:
                invoice.notes = f"Payment Terms: {payment_terms}"
        
        invoice.save()
        messages.success(request, 'Billing details updated successfully.')
        return redirect('invoice_view', invoice_id=invoice.id)
    
    return redirect('invoice_view', invoice_id=invoice_id)


@login_required
def update_invoice_items(request, invoice_id):
    """Update invoice items including item codes, descriptions, quantities, amounts, due dates, status, and percentages."""
    if request.method == 'POST':
        invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
        
        # Process form data to extract items
        items_data = []
        item_counter = 1
        
        while f'item_code_{item_counter}' in request.POST:
            item_code = request.POST.get(f'item_code_{item_counter}', '').strip()
            description = request.POST.get(f'description_{item_counter}', '').strip()
            quantity = request.POST.get(f'quantity_{item_counter}', '1')
            amount = request.POST.get(f'amount_{item_counter}', '0')
            due_date = request.POST.get(f'due_date_{item_counter}', '')
            status = request.POST.get(f'status_{item_counter}', 'Pending')
            percentage = request.POST.get(f'percentage_{item_counter}', '0')
            
            if item_code or description:  # Only add if there's content
                try:
                    quantity = int(quantity) if quantity else 1
                    amount = float(amount) if amount else 0.0
                    percentage = float(percentage) if percentage else 0.0
                    
                    items_data.append({
                        'item_code': item_code,
                        'description': description,
                        'quantity': quantity,
                        'amount': amount,
                        'due_date': due_date,
                        'status': status,
                        'percentage': percentage
                    })
                except (ValueError, TypeError):
                    messages.error(request, f'Invalid data for item {item_counter}. Please check your inputs.')
                    return redirect('invoice_view', invoice_id=invoice.id)
            
            item_counter += 1
        
        if not items_data:
            messages.error(request, 'At least one item is required.')
            return redirect('invoice_view', invoice_id=invoice.id)
        
        # Validate total percentage doesn't exceed 100%
        total_percentage = sum(item['percentage'] for item in items_data)
        if total_percentage > 100:
            messages.error(request, f'Total percentage ({total_percentage:.2f}%) cannot exceed 100%.')
            return redirect('invoice_view', invoice_id=invoice.id)
        
        # Update invoice with the first item's data (primary item)
        primary_item = items_data[0]
        invoice.qty = primary_item['quantity']
        
        # Calculate new unit price based on total amount
        total_amount = sum(item['amount'] for item in items_data)
        if total_amount > 0:
            # Update unit price to reflect the new total
            invoice.unit_price = Decimal(str(total_amount))
        
        # Store items data in notes field as JSON for future reference
        import json
        items_json = json.dumps(items_data, default=str)
        
        # Update or add items data to notes
        if invoice.notes:
            # Remove existing items data if present
            lines = invoice.notes.split('\n')
            filtered_lines = [line for line in lines if not line.startswith('Items Data:')]
            invoice.notes = '\n'.join(filtered_lines)
            if invoice.notes.strip():
                invoice.notes += f"\nItems Data: {items_json}"
            else:
                invoice.notes = f"Items Data: {items_json}"
        else:
            invoice.notes = f"Items Data: {items_json}"
        
        # Update due date if provided in first item
        if primary_item['due_date']:
            from datetime import datetime
            try:
                invoice.due_date = datetime.strptime(primary_item['due_date'], '%Y-%m-%d').date()
            except ValueError:
                pass  # Keep existing due date if invalid format
        
        invoice.save()
        
        # Update related tranche payment status if applicable
        if invoice.tranche:
            tranche_payment = invoice.tranche
            # Update status based on the primary item status
            if primary_item['status'] in ['Received', 'Pending', 'Overdue']:
                tranche_payment.status = primary_item['status']
                
                # Update received amount if status is 'Received'
                if primary_item['status'] == 'Received' and primary_item['amount'] > 0:
                    tranche_payment.received_amount = Decimal(str(primary_item['amount']))
                    tranche_payment.date_received = now().date()
                
                tranche_payment.save()
        
        messages.success(request, f'Invoice items updated successfully. {len(items_data)} item(s) processed.')
        return redirect('invoice_view', invoice_id=invoice.id)
    
    return redirect('invoice_view', invoice_id=invoice_id)


@login_required
def update_invoice(request, invoice_id):
    """Unified view to handle all invoice updates: bill-to info, billing details, and items."""
    if request.method == 'POST':
        invoice = get_object_or_404(BillingInvoice, pk=invoice_id)
        
        # Debug: Log all POST data
        print(f"DEBUG: POST data for invoice {invoice_id}:")
        for key, value in request.POST.items():
            print(f"  {key}: {value}")
        
        try:
            # Update bill-to information
            if 'client_name' in request.POST:
                invoice.client_name = request.POST.get('client_name', invoice.client_name)
            if 'client_address' in request.POST:
                invoice.client_address = request.POST.get('client_address', invoice.client_address)
            if 'client_tin' in request.POST:
                invoice.client_tin = request.POST.get('client_tin', invoice.client_tin)
            
            # Update billing details (dates only - don't recalculate financials)
            if 'issue_date' in request.POST:
                issue_date = request.POST.get('issue_date')
                if issue_date:
                    from datetime import datetime
                    invoice.issue_date = datetime.strptime(issue_date, '%Y-%m-%d').date()
            
            if 'due_date' in request.POST:
                due_date = request.POST.get('due_date')
                if due_date:
                    from datetime import datetime
                    invoice.due_date = datetime.strptime(due_date, '%Y-%m-%d').date()
            
            if 'reference_no' in request.POST:
                reference_no = request.POST.get('reference_no')
                if reference_no:
                    invoice.reference_no = reference_no
            
            # Handle payment terms in notes field
            if 'payment_terms' in request.POST:
                payment_terms = request.POST.get('payment_terms', '').strip()
                # Always update payment terms, even if empty
                if invoice.notes:
                    # Check if payment terms are already in notes
                    if 'Payment Terms:' not in invoice.notes:
                        if payment_terms:  # Only add if not empty
                            invoice.notes += f"\nPayment Terms: {payment_terms}"
                    else:
                        # Update existing payment terms
                        lines = invoice.notes.split('\n')
                        updated_lines = []
                        for line in lines:
                            if line.startswith('Payment Terms:'):
                                if payment_terms:  # Only add if not empty
                                    updated_lines.append(f'Payment Terms: {payment_terms}')
                                # If empty, skip this line (effectively removing it)
                            else:
                                updated_lines.append(line)
                        invoice.notes = '\n'.join(updated_lines)
                else:
                    if payment_terms:  # Only create notes if payment terms is not empty
                        invoice.notes = f"Payment Terms: {payment_terms}"
            
            # Process invoice items
            items_data = []
            item_counter = 1
            
            while f'item_code_{item_counter}' in request.POST:
                item_code = request.POST.get(f'item_code_{item_counter}', '').strip()
                description = request.POST.get(f'description_{item_counter}', '').strip()
                quantity = request.POST.get(f'quantity_{item_counter}', '1')
                amount = request.POST.get(f'amount_{item_counter}', '0')
                due_date = request.POST.get(f'due_date_{item_counter}', '')
                status = request.POST.get(f'status_{item_counter}', 'Pending')
                percentage = request.POST.get(f'percentage_{item_counter}', '0')
                
                if item_code or description:  # Only add if there's content
                    try:
                        quantity = int(quantity) if quantity else 1
                        amount = float(amount) if amount else 0.0
                        percentage = float(percentage) if percentage else 0.0
                        
                        items_data.append({
                            'item_code': item_code,
                            'description': description,
                            'quantity': quantity,
                            'amount': amount,
                            'due_date': due_date,
                            'status': status,
                            'percentage': percentage
                        })
                    except (ValueError, TypeError):
                        messages.error(request, f'Invalid data for item {item_counter}. Please check your inputs.')
                        return redirect('invoice_view', invoice_id=invoice.id)
                
                item_counter += 1
            
            # Process items if any were provided
            if items_data:
                # Validate total percentage doesn't exceed 100%
                total_percentage = sum(item['percentage'] for item in items_data)
                if total_percentage > 100:
                    messages.error(request, f'Total percentage ({total_percentage:.2f}%) cannot exceed 100%.')
                    return redirect('invoice_view', invoice_id=invoice.id)
                
                # Check if this is a financial change based on the flag from frontend
                is_financial_change = request.POST.get('financial_change', 'false') == 'true'
                
                # Only update financial fields if this is actually a financial change
                if is_financial_change:
                    # Update invoice with the first item's data (primary item)
                    primary_item = items_data[0]
                    invoice.qty = primary_item['quantity']
                    
                    # Update unit_price for financial changes
                    total_amount = sum(item['amount'] for item in items_data)
                    if total_amount > 0:
                        current_calculated_total = float(invoice.unit_price) if invoice.unit_price else 0.0
                        invoice.unit_price = Decimal(str(total_amount))
                        print(f"DEBUG: Financial change detected - Updated unit_price from {current_calculated_total} to {total_amount}")
                else:
                    print(f"DEBUG: Non-financial change detected - Preserving original unit_price: {invoice.unit_price}")
                
                # Store items data in notes field as JSON for future reference
                import json
                items_json = json.dumps(items_data, default=str)
                
                # Update or add items data to notes
                if invoice.notes:
                    # Remove existing items data if present
                    lines = invoice.notes.split('\n')
                    filtered_lines = [line for line in lines if not line.startswith('Items Data:')]
                    invoice.notes = '\n'.join(filtered_lines)
                    if invoice.notes.strip():
                        invoice.notes += f"\nItems Data: {items_json}"
                    else:
                        invoice.notes = f"Items Data: {items_json}"
                else:
                    invoice.notes = f"Items Data: {items_json}"
                
                # Only update financial-related fields for financial changes
                if is_financial_change and items_data:
                    primary_item = items_data[0]
                    
                    # Update due date if provided in first item and not already set from billing details
                    if primary_item['due_date'] and 'due_date' not in request.POST:
                        from datetime import datetime
                        try:
                            invoice.due_date = datetime.strptime(primary_item['due_date'], '%Y-%m-%d').date()
                        except ValueError:
                            pass  # Keep existing due date if invalid format
                    
                    # Update related tranche payment status if applicable
                    if invoice.tranche:
                        tranche_payment = invoice.tranche
                        # Update status based on the primary item status
                        if primary_item['status'] in ['Received', 'Pending', 'Overdue']:
                            tranche_payment.status = primary_item['status']
                            
                            # Update received amount if status is 'Received'
                            if primary_item['status'] == 'Received' and primary_item['amount'] > 0:
                                tranche_payment.received_amount = Decimal(str(primary_item['amount']))
                                tranche_payment.date_received = now().date()
                            
                            tranche_payment.save()
            
            # Save the invoice without triggering recalculations
            invoice.save(update_fields=['client_name', 'client_address', 'client_tin', 'issue_date', 'due_date', 'reference_no', 'notes'])
            print(f"DEBUG: Invoice saved with preserved unit_price: {invoice.unit_price}, vat_rate: {invoice.vat_rate}")
            
            # Success message
            updated_sections = []
            if 'client_name' in request.POST or 'client_address' in request.POST or 'client_tin' in request.POST:
                updated_sections.append('billing information')
            if 'issue_date' in request.POST or 'due_date' in request.POST or 'reference_no' in request.POST or 'payment_terms' in request.POST:
                updated_sections.append('billing details')
            if items_data:
                updated_sections.append(f'{len(items_data)} item(s)')
            
            if updated_sections:
                messages.success(request, f'Invoice updated successfully: {", ".join(updated_sections)}.')
            else:
                messages.success(request, 'Invoice updated successfully.')
            
            return redirect('invoice_view', invoice_id=invoice.id)
            
        except Exception as e:
            messages.error(request, f'Error updating invoice: {str(e)}')
            return redirect('invoice_view', invoice_id=invoice.id)
    
    return redirect('invoice_view', invoice_id=invoice_id)
