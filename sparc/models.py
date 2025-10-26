from django.db import models
from django.contrib.auth.models import User  # Use Django's built-in User model
from django.db.models import Sum, Q
from django.utils.timezone import now
from decimal import Decimal, ROUND_HALF_UP
Decimal('0.0')



class Team(models.Model):
    name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=100, unique=True, null=True, blank=True)  # Keep it nullable
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)  # To soft-delete teams

    def __str__(self):
        return self.display_name or self.name

    class Meta:
        ordering = ['name']

    @classmethod
    def get_active_choices(cls):
        return [(team.name, team.display_name or team.name) for team in cls.objects.filter(is_active=True)]

    def total_sales(self):
        """Calculate total sales for the entire team"""
        return Sale.objects.filter(agent__team=self).aggregate(Sum('price'))['price__sum'] or 0

class Developer(models.Model):
    name = models.CharField(max_length=200, unique=True)
    address = models.TextField(blank=True, null=True)
    tin_number = models.CharField(max_length=50, blank=True, null=True)
    image = models.ImageField(upload_to='developer_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Property(models.Model):
    name = models.CharField(max_length=200)
    developer = models.ForeignKey(Developer, on_delete=models.SET_NULL, null=True, blank=True)
    image = models.ImageField(upload_to='property_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Properties"
        unique_together = ['name', 'developer']  # Prevent duplicate properties for same developer

    def __str__(self):
        if self.developer:
            return f"{self.name} - {self.developer.name}"
        return self.name
    
# models.py
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='profile_images/', default='default.jpg')
    bio = models.TextField(blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    address = models.TextField(null=True, blank=True)
    is_approved = models.BooleanField(default=False)  # Add this field
    joining_date = models.DateField(null=True, blank=True)  # Add this field
    commission_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)  # Add this field
    total_commission_earned = models.DecimalField(max_digits=12, decimal_places=2, default=0) 

    role = models.CharField(max_length=50, choices=[
        ('Sales Agent', 'Sales Agent'),
        ('Sales Supervisor', 'Sales Supervisor'),
        ('Sales Manager', 'Sales Manager'),
    ])
    team = models.ForeignKey(Team, on_delete=models.SET_NULL, null=True, blank=True)
    is_approved = models.BooleanField(default=False)
    
    def can_approve_user(self, other_user):
        """Check if this user can approve another user"""
        if not self.user.is_staff or self.role != 'Sales Manager':
            return False
        return self.team == other_user.profile.team
        
    def __str__(self):
        return f"{self.user.username}'s profile"
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def get_total_sales(self):
        return Sale.objects.filter(user=self.user).aggregate(
            total=Sum('amount')
        )['total'] or 0
    
    def get_active_sales(self):
        return Sale.objects.filter(
            user=self.user, 
            status='Active'
        ).aggregate(total=Sum('amount'))['total'] or 0




class CommissionSlip(models.Model):
    sales_agent_name = models.CharField(max_length=100)    
    buyer_name = models.CharField(max_length=255)
    project_name = models.CharField(max_length=255)
    unit_id = models.CharField(max_length=100)
    total_selling_price = models.FloatField(null=True, blank=True)
    commission_rate = models.FloatField(null=True, blank=True)
    incentive_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    cash_advance = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    cash_advance_tax = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    date = models.DateField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_slips')
    created_at = models.DateTimeField(null=True, blank=True)
    is_full_breakdown = models.BooleanField(default=False)
    source = models.CharField(max_length=50, default='standard', help_text="Source of the commission slip (e.g., 'standard', 'full_breakdown')")
    withholding_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)  # Agent tax rate
    operation_manager_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)  # Operation Manager tax rate
    co_founder_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)  # Co-Founder tax rate
    founder_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)  # Founder tax rate
    sales_manager_name = models.CharField(max_length=100, null=True, blank=True)
    manager_commission_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    signature = models.ImageField(upload_to='signatures/', null=True, blank=True)

    def __str__(self):
        return f"Commission Slip for {self.sales_agent_name}"
    
class CommissionSlip2(models.Model):
    total_selling_price_manager = models.DecimalField(max_digits=12, decimal_places=2)
    operation_manager_rate = models.DecimalField(max_digits=5, decimal_places=2)
    co_founder_rate = models.DecimalField(max_digits=5, decimal_places=2)
    founder_rate = models.DecimalField(max_digits=5, decimal_places=2)
    funds_rate = models.DecimalField(max_digits=5, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Commission Slip - {self.id}"

class CommissionDetail(models.Model):
    slip = models.ForeignKey(CommissionSlip, on_delete=models.CASCADE, related_name='details')
    position = models.CharField(max_length=100, default="N/A")
    particulars = models.CharField(max_length=255, default="N/A")
    commission_rate = models.DecimalField(max_digits=5, decimal_places=2)
    base_commission = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    gross_commission = models.DecimalField(max_digits=12, decimal_places=2)
    withholding_tax = models.DecimalField(max_digits=12, decimal_places=2)
    net_commission = models.DecimalField(max_digits=12, decimal_places=2)
    agent_name = models.CharField(max_length=100, null=True, blank=True)
    partial_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=100)
    withholding_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)  # Add this field
    percentage_of_particulars = models.DecimalField(max_digits=5, decimal_places=2, default=100, null=True, blank=True)  # Display-only field for particulars percentage

    def __str__(self):
        return f"{self.position} - {self.particulars}"


class Commission(models.Model):
    date_released = models.DateField()
    release_number = models.CharField(max_length=50)
    project_name = models.CharField(max_length=200)
    developer = models.CharField(max_length=200)
    buyer = models.CharField(max_length=200)
    agent = models.ForeignKey(User, on_delete=models.CASCADE)
    commission_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.release_number} - {self.project_name}"

    class Meta:
        ordering = ['-date_released']


class TrancheRecord(models.Model):
    project_name = models.CharField(max_length=255)
    agent_name = models.CharField(max_length=255)
    phase = models.CharField(max_length=100)
    unit_id = models.CharField(max_length=100)
    buyer_name = models.CharField(max_length=255)
    reservation_date = models.DateField()
    total_contract_price = models.DecimalField(max_digits=12, decimal_places=2)
    commission_rate = models.DecimalField(max_digits=5, decimal_places=2)
    process_fee_percentage = models.DecimalField(max_digits=8, decimal_places=5, default=0)
    withholding_tax_rate = models.DecimalField(max_digits=8, decimal_places=5, default=10.00000)
    option1_percentage = models.DecimalField(max_digits=5, decimal_places=2)
    option2_percentage = models.DecimalField(max_digits=5, decimal_places=2)
    option1_tax_rate = models.DecimalField(max_digits=8, decimal_places=5, default=10.00000)
    option2_tax_rate = models.DecimalField(max_digits=8, decimal_places=5, default=10.00000)
    tranche_option = models.CharField(max_length=20)
    number_months = models.IntegerField()
    vat_rate = models.DecimalField(max_digits=8, decimal_places=5, default=12.00000)
    net_of_vat_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    deduction_type = models.CharField(max_length=50, null=True, blank=True)
    other_deductions = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    deduction_tax_rate = models.DecimalField(max_digits=8, decimal_places=5, default=10.00000)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_tranches')

    def __str__(self):
        return f"{self.project_name} - {self.buyer_name}"
    
    def delete(self, *args, **kwargs):
        """
        Custom delete method to ensure proper cleanup of all related voucher data.
        This ensures referential integrity even if deletion happens outside of views.
        Deletes:
        - Individual vouchers (BillingInvoice objects)
        - Individual commission records (DP-{id} and LTO-{id} format)
        - Combined commission vouchers (COMBINED-DP-{id} format)
        """
        # Get all tranche payments before deletion for voucher cleanup
        tranche_payments = list(self.payments.all())
        
        # Track what we're deleting for logging
        individual_vouchers_count = 0
        combined_vouchers_affected = set()
        
        # Delete individual vouchers (BillingInvoice objects)
        for payment in tranche_payments:
            # Count and delete all invoices (individual vouchers) for this tranche payment
            invoices = payment.invoices.all()
            individual_vouchers_count += invoices.count()
            invoices.delete()
            
            # Track combined voucher numbers for deletion
            if payment.combined_voucher_number:
                combined_vouchers_affected.add(payment.combined_voucher_number)
        
        # Delete individual commission records using the tranche ID
        tranche_id_str = str(self.id)
        individual_commission_deleted = Commission.objects.filter(
            Q(release_number__startswith=f'DP-{tranche_id_str}') | 
            Q(release_number__startswith=f'LTO-{tranche_id_str}')
        ).count()
        Commission.objects.filter(
            Q(release_number__startswith=f'DP-{tranche_id_str}') | 
            Q(release_number__startswith=f'LTO-{tranche_id_str}')
        ).delete()
        
        # Delete combined commission vouchers associated with this tranche
        # Combined vouchers have format: COMBINED-DP-{record_id}-{tranche_numbers}
        combined_commission_deleted = 0
        if combined_vouchers_affected:
            for voucher_number in combined_vouchers_affected:
                # Delete the Commission record for this combined voucher
                deleted_count = Commission.objects.filter(release_number=voucher_number).count()
                Commission.objects.filter(release_number=voucher_number).delete()
                combined_commission_deleted += deleted_count
            
            # Unlink any other tranches that were part of these combined vouchers
            # This prevents orphaned references in other tranche records
            TranchePayment.objects.filter(
                combined_voucher_number__in=combined_vouchers_affected
            ).update(combined_voucher_number=None)
        
        # Log the cleanup for debugging
        print(f"TrancheRecord {self.id} deletion cleanup: "
              f"{individual_vouchers_count} individual vouchers, "
              f"{individual_commission_deleted} individual commission records, "
              f"{combined_commission_deleted} combined commission records, "
              f"{len(combined_vouchers_affected)} combined voucher(s) deleted")
        
        # Call the parent delete method to actually delete the record
        # This will cascade delete TranchePayment objects due to the ForeignKey relationship
        super().delete(*args, **kwargs)

class TranchePayment(models.Model):
    tranche_record = models.ForeignKey(TrancheRecord, on_delete=models.CASCADE, related_name='payments')
    tranche_number = models.IntegerField()
    expected_date = models.DateField()
    expected_amount = models.DecimalField(max_digits=12, decimal_places=2)
    received_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    date_received = models.DateField(null=True, blank=True)
    is_lto = models.BooleanField(default=False)  # To distinguish between DP and LTO tranches
    status = models.CharField(max_length=20, default='Pending')  # Pending, Partial, Received
    initial_balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)  # Add initial balance field
    combined_voucher_number = models.CharField(max_length=100, null=True, blank=True)  # Track which combined voucher this tranche belongs to

    def __str__(self):
        return f"Tranche {self.tranche_number} for {self.tranche_record.project_name}"

    class Meta:
        ordering = ['tranche_number']


class BillingInvoice(models.Model):
    """Invoice generated for each TranchePayment to request commission release."""
    tranche = models.ForeignKey('TranchePayment', on_delete=models.CASCADE, related_name='invoices')
    invoice_no = models.CharField(max_length=20, unique=True)
    reference_no = models.CharField(max_length=100, blank=True, null=True)  # To store dynamic reference
    issue_date = models.DateField(default=now)
    due_date = models.DateField()  # should mirror tranche.expected_date
    qty = models.PositiveIntegerField(default=1)
    unit_price = models.DecimalField(max_digits=12, decimal_places=2)
    vat_rate = models.DecimalField(max_digits=5, decimal_places=2, default=12)
    notes = models.TextField(blank=True)
    prepared_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='prepared_invoices')
    prepared_by_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # E-signature fields
    checked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='checked_invoices')
    checked_by_date = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_invoices')
    approved_by_date = models.DateTimeField(null=True, blank=True)
    prepared_by_signature = models.ImageField(upload_to='signatures/', null=True, blank=True)
    checked_by_signature = models.ImageField(upload_to='signatures/', null=True, blank=True)
    approved_by_signature = models.ImageField(upload_to='signatures/', null=True, blank=True)

    # Fields for editable 'Bill To' section
    client_name = models.CharField(max_length=255, default='650 ALLIED INC.')
    client_address = models.TextField(default='2nd Flr B and S Bldg 1644 Evangelista St. Bangkal\nMakati City, Metro Manila 1233')
    client_tin = models.CharField(max_length=50, default='755-023-386-000')

    class Meta:
        ordering = ['-issue_date']

    def __str__(self):
        return f"Invoice {self.invoice_no} – {self.tranche}"


class CommissionSlip3(models.Model):
    sales_agent_name = models.CharField(max_length=100)    
    supervisor_name = models.CharField(max_length=100)
    buyer_name = models.CharField(max_length=255)
    project_name = models.CharField(max_length=255)
    unit_id = models.CharField(max_length=100)
    total_selling_price = models.FloatField(null=True, blank=True)
    incentive_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    cash_advance = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    cash_advance_tax = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    date = models.DateField(null=True, blank=True)
    # --- Sales Manager additions ---
    manager_name = models.CharField(max_length=100, null=True, blank=True)
    manager_commission_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    manager_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)
    # --------------------------------
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_slips3')
    created_at = models.DateTimeField(null=True, blank=True)
    withholding_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)  # Agent tax rate
    supervisor_withholding_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)  # New supervisor tax rate
    signature = models.ImageField(upload_to='signatures/', null=True, blank=True)
    source = models.CharField(max_length=50, default='standard', help_text="Source of the commission slip (e.g., 'standard', 'manual_breakdown')")

    def __str__(self):
        return f"Commission Slip for {self.sales_agent_name} with Supervisor {self.supervisor_name}"

class CommissionDetail3(models.Model):
    slip = models.ForeignKey(CommissionSlip3, on_delete=models.CASCADE, related_name='details')
    position = models.CharField(max_length=100, default="N/A")
    particulars = models.CharField(max_length=255, default="N/A")
    commission_rate = models.DecimalField(max_digits=5, decimal_places=2)
    base_commission = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    gross_commission = models.DecimalField(max_digits=12, decimal_places=2)
    withholding_tax = models.DecimalField(max_digits=12, decimal_places=2)
    net_commission = models.DecimalField(max_digits=12, decimal_places=2)
    agent_name = models.CharField(max_length=100, null=True, blank=True)
    partial_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=100)
    withholding_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)
    is_supervisor = models.BooleanField(default=False)  # New field to distinguish supervisor from agent
    percentage_of_particulars = models.DecimalField(max_digits=5, decimal_places=2, default=100, null=True, blank=True)  # Display-only field for particulars percentage

    def __str__(self):
        return f"{self.position} - {self.particulars}"


class ProblemReport(models.Model):
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]
    
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('urgent', 'Urgent'),
    ]
    
    CATEGORY_CHOICES = [
        ('login', 'Login Issues'),
        ('password', 'Password Problems'),
        ('account', 'Account Access'),
        ('technical', 'Technical Issues'),
        ('other', 'Other'),
    ]
    
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=20, blank=True, null=True)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='other')
    subject = models.CharField(max_length=200)
    description = models.TextField()
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_problems')
    resolved_at = models.DateTimeField(null=True, blank=True)
    admin_notes = models.TextField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)  # Browser info
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.subject} - {self.name} ({self.get_status_display()})"
