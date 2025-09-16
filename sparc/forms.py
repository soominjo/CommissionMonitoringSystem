from django import forms
from django.contrib.auth.models import User
from .models import *
from django.forms import DateInput


# Role choices
ROLE_CHOICES = [
    ('Sales Agent', 'Sales Agent'),
    ('Sales Supervisor', 'Sales Supervisor'),
    ('Sales Manager', 'Sales Manager'),
]

TEAM_CHOICES = [
    ('Fiery Achievers', 'Fiery Achievers'),
    ('Blazing SPARCS', 'Blazing SPARCS'),
    ('Feisty Heroine', 'Feisty Heroine'),
    ('Shining Phoeninx', 'Shining Phoeninx'),
    ('Flameborn Champions', 'Flameborn Champions'),
    
]

# forms.py
class SignUpForm(forms.ModelForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'minlength': 5}),
        min_length=5,
        max_length=150,
        label="Username",
        help_text="Required. 5-150 characters. Letters, digits and @/./+/-/_ only."
    )
    email = forms.EmailField(required=True, label="Email Address")
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"minlength": 8}),
        label="Password",
        help_text="Must contain at least 8 characters."
    )
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={"minlength": 8}), label="Confirm Password")
    role = forms.ChoiceField(choices=ROLE_CHOICES, required=True, label="Select Role")
    team = forms.ModelChoiceField(
        queryset=Team.objects.filter(is_active=True),
        required=True,
        label="Select Team",
        empty_label="Choose a team"
    )
    phone_number = forms.RegexField(
        regex=r'^09\d{9}$',
        max_length=11,
        required=False,
        label="Phone Number",
        error_messages={'invalid': 'Enter a valid Philippine number e.g. 09123456789'},
        widget=forms.TextInput(attrs={'placeholder': '09123456789', 'maxlength': '11', 'pattern': '09\\d{9}'})
    )
    first_name = forms.CharField(max_length=100, required=False, label="First Name")
    last_name = forms.CharField(max_length=100, required=False, label="Last Name")

    class Meta:
        model = User
        fields = ['username', 'email', 'role', 'password1', 'password2', 'phone_number', 'first_name', 'last_name']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['team'].queryset = Team.objects.filter(is_active=True).order_by('name')
        # Ensure email is required in UI as well
        self.fields['email'].required = True

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get("username")
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and len(password1) < 8:
            self.add_error('password1', "Password must be at least 8 characters long")

        if username and len(username) < 5:
            self.add_error('username', "Username must be at least 5 characters long")
        
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match")
        
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
            profile = Profile.objects.create(
                user=user,
                role=self.cleaned_data.get('role'),
                bio=self.cleaned_data.get('bio'),
                phone_number=self.cleaned_data.get('phone_number'),
                first_name=self.cleaned_data.get('first_name'),
                last_name=self.cleaned_data.get('last_name'),
                team=self.cleaned_data.get('team')  # Add this line
            )
        return user
    
class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['phone_number', 'bio', 'role']  # Include bio here

        

class CommissionSlipForm(forms.ModelForm):
    sales_agent_name = forms.CharField(required=False)

    date = forms.DateField(
        required=True,
        widget=DateInput(attrs={
            'type': 'date',
            'class': 'w-full border-gray-300 rounded-lg shadow-sm focus:ring-blue-500 focus:border-blue-500 p-2'
        })
    )

    PARTICULARS_CHOICES = [
        ("PARTIAL COMM", "PARTIAL COMM"),
        ("FULL COMM", "FULL COMM"), 
        ("INCENTIVES", "INCENTIVES"),
    ]
    
    particulars = forms.ChoiceField(choices=PARTICULARS_CHOICES, required=False)
    incentive_amount = forms.DecimalField(required=False, initial=0.0, widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0'}))
    cash_advance = forms.DecimalField(required=False, initial=0.0, widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0'}))
    fee = forms.DecimalField(required=False, initial=0.0, widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0'}))
    withholding_tax_rate = forms.DecimalField(
        max_digits=5,
        decimal_places=2,
        required=True,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'}),
        label="Withholding Tax Rate (%)"
    )
    operation_manager_tax_rate = forms.DecimalField(
        required=False,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )
    co_founder_tax_rate = forms.DecimalField(
        required=False,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )
    founder_tax_rate = forms.DecimalField(
        required=False,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )
    funds_tax_rate = forms.DecimalField(
        required=False,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )
    partial_percentage = forms.DecimalField(
        required=False,
        initial=100.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )

    class Meta:
        model = CommissionSlip
        fields = [
            'sales_agent_name', 'buyer_name', 'project_name', 'unit_id',
            'total_selling_price', 'commission_rate', 'particulars',
            'incentive_amount', 'cash_advance', 'fee', 'date',
            'withholding_tax_rate', 'operation_manager_tax_rate',
            'co_founder_tax_rate', 'founder_tax_rate', 'sales_manager_name', 'manager_commission_rate',
            'funds_tax_rate', 'partial_percentage'
        ]


class CommissionForm(forms.Form):
    project_name = forms.CharField(max_length=100)
    unit_id = forms.CharField(max_length=100)
    buyer_name = forms.CharField(max_length=100)
    agent_name = forms.ModelChoiceField(
        queryset=User.objects.filter(
            profile__is_approved=True,
            profile__role__in=['Sales Agent', 'Sales Supervisor', 'Sales Manager']
        ).select_related('profile'),
        empty_label="Select an Agent",
        to_field_name="id",
        label="Agent's Name"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Update the agent_name queryset to include only approved users
        self.fields['agent_name'].queryset = User.objects.filter(
            profile__is_approved=True,
            profile__role__in=['Sales Agent', 'Sales Supervisor', 'Sales Manager']
        ).select_related('profile')

        # Customize the display of agent names in the dropdown
        self.fields['agent_name'].label_from_instance = lambda obj: f"{obj.get_full_name()} ({obj.profile.role})"

    phase = forms.IntegerField(required=False, initial=0)
    reservation_date = forms.DateField(
    required=True,
    widget=DateInput(attrs={
        'type': 'date',
        'class': 'w-full border-gray-300 rounded-lg shadow-sm focus:ring-blue-500 focus:border-blue-500 p-2'
    })
)
    number_months= forms.IntegerField()

    total_contract_price = forms.DecimalField(
        max_digits=12,
        decimal_places=2,
        widget=forms.TextInput(attrs={'class': 'comma-format'})
    )

    # Net of VAT amount that will be deducted from the Total Contract Price to derive the Total Selling Price
    net_of_vat_amount = forms.DecimalField(
        max_digits=12,
        decimal_places=2,
        required=False,
        initial=1.12,
        widget=forms.TextInput(attrs={'class': 'comma-format'}),
        label="Net of VAT Amount (₱)"
    )
    commission_rate = forms.DecimalField(max_digits=5, decimal_places=2, initial=7)
    # VAT rate field allows users to specify VAT percentage (default 12%)
    vat_rate = forms.DecimalField(
        max_digits=8,
        decimal_places=5,
        required=True,
        initial=12.00000,
        widget=forms.NumberInput(attrs={'step': '0.00001', 'min': '0', 'max': '100'}),
        label="VAT Rate (%)"
    )
    tranche_option = forms.ChoiceField(
        choices=[
            ("bi_monthly", "Bi-Monthly"),
            ("quarterly", "Quarterly"),
            ("bi_6_months", "6 Months"),
            ("bi_9_months", "9 Months"),
        ]
    )
    tax_rate = forms.DecimalField(max_digits=5, decimal_places=2, required=False, label="Tax Rate (%)")
    withholding_tax_rate = forms.DecimalField(
        max_digits=8,
        decimal_places=5,
        required=True,
        initial=10.00000,
        widget=forms.NumberInput(attrs={'step': '0.00001', 'min': '0', 'max': '100'}),
        label="Withholding Tax Rate (%)"
    )
    process_fee_percentage = forms.DecimalField(
        max_digits=8,
        decimal_places=5,
        required=False,
        initial=0,
        widget=forms.NumberInput(attrs={'step': '0.00001'}),
        label="LMF/PF (%)"
    )

    # New fields for "Condition for Commission Rate"
    option1_percentage = forms.DecimalField(max_digits=5, decimal_places=2, initial=50, label="Within Down Payment Period (%)")
    option1_tax_rate = forms.DecimalField(
        max_digits=8,
        decimal_places=5,
        required=True,
        initial=10.00000,
        widget=forms.NumberInput(attrs={'step': '0.00001', 'min': '0', 'max': '100'}),
        label="Tax Rate for DP Period (%)"
    )

    option2_percentage = forms.DecimalField(max_digits=5, decimal_places=2, initial=50, label="Upon Loan Take Out (%)")
    option2_tax_rate = forms.DecimalField(
        max_digits=8,
        decimal_places=5,
        required=True,
        initial=10.00000,
        widget=forms.NumberInput(attrs={'step': '0.00001', 'min': '0', 'max': '100'}),
        label="Tax Rate for Loan Take Out (%)"
    )

    deduction_tax_rate = forms.DecimalField(
        max_digits=8,
        decimal_places=5,
        required=False,
        initial=10.00000,
        widget=forms.NumberInput(attrs={'step': '0.00001', 'min': '0', 'max': '100'}),
        label="Tax Rate for Other Deduction (%)"
    )

      # New fields for dynamic deductions
    deduction_type = forms.ChoiceField(
        choices=[
            ("reservation_fee", "Reservation Fee"),
            ("processing_fee", "Processing Fee"),
            ("reservation_incentives", "Reservation Incentives"),
        ],
        label="Deduction Type",
        required=False,
    )
    other_deductions = forms.DecimalField(
        max_digits=12,
        decimal_places=2,
        required=False,
        initial=0,
        label="Other Deductions (₱)",
        widget=forms.TextInput(attrs={'class': 'comma-format'})
    )


class CommissionSlipForm3(forms.ModelForm):
    date = forms.DateField(
        required=True,
        widget=DateInput(attrs={
            'type': 'date',
            'class': 'w-full border-gray-300 rounded-lg shadow-sm focus:ring-blue-500 focus:border-blue-500 p-2'
        })
    )

    PARTICULARS_CHOICES = [
        ("PARTIAL COMM", "PARTIAL COMM"),
        ("FULL COMM", "FULL COMM"), 
        ("INCENTIVES", "INCENTIVES"),
    ]
    
    particulars = forms.ChoiceField(choices=PARTICULARS_CHOICES, required=False)
    incentive_amount = forms.DecimalField(required=False, initial=0.0, widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0'}))
    cash_advance = forms.DecimalField(required=False, initial=0.0, widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0'}))
    fee = forms.DecimalField(required=False, initial=0.0, widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0'}))
    withholding_tax_rate = forms.DecimalField(
        required=True,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )
    supervisor_withholding_tax_rate = forms.DecimalField(
        required=True,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )
    # --- Sales Manager additions ---
    manager_commission_rate = forms.DecimalField(
        required=False,
        initial=0,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0'})
    )
    manager_tax_rate = forms.DecimalField(
        required=False,
        initial=10.00,
        widget=forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'max': '100'})
    )
    manager_name = forms.CharField(required=False, max_length=150)
    # --------------------------------

    class Meta:
        model = CommissionSlip3
        fields = [
            'sales_agent_name',
            'supervisor_name',
            'manager_name',
            'buyer_name',
            'project_name',
            'unit_id',
            'total_selling_price',
            'incentive_amount',
            'cash_advance',
            'fee',
            'date',
            'withholding_tax_rate',
            'supervisor_withholding_tax_rate',
            'manager_commission_rate',
            'manager_tax_rate'
        ]


class ExcelUploadForm(forms.Form):
    """Form for uploading Excel files for tranche calculations"""
    excel_file = forms.FileField(
        label="Upload Excel File",
        help_text="Upload an Excel file (.xlsx) containing tranche data for processing",
        widget=forms.FileInput(attrs={
            'class': 'w-full p-3 border-2 border-dashed border-gray-300 rounded-lg hover:border-blue-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-colors duration-200',
            'accept': '.xlsx,.xls',
            'id': 'excel-file-input'
        })
    )

    def clean_excel_file(self):
        """Validate the uploaded Excel file"""
        file = self.cleaned_data.get('excel_file')
        
        if not file:
            raise forms.ValidationError("Please select a file to upload.")
        
        # Check file extension
        if not file.name.lower().endswith(('.xlsx', '.xls')):
            raise forms.ValidationError("Please upload a valid Excel file (.xlsx or .xls).")
        
        # Check file size (limit to 10MB)
        if file.size > 10 * 1024 * 1024:
            raise forms.ValidationError("File size must be less than 10MB.")
        
        # Check if file is empty
        if file.size == 0:
            raise forms.ValidationError("The uploaded file is empty.")
        
        return file
