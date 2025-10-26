# Testing Guide: Loan Take-Out Actual Commission Fix

## Quick Test Steps

### Test 1: Basic Save Functionality
1. Open any tranche in edit mode: `/sparc/edit_tranche/<id>/`
2. Scroll to "Loan Take Out Schedule" section
3. Enter a value (e.g., 50000) in the "Actual Commission" field
4. Select today's date in the "Date Received" field
5. Click "Save All Changes"
6. **Expected Result**: Success message appears, page redirects to view page

### Test 2: Verify Data Persistence
1. After saving (from Test 1), click "Edit" button again
2. **Expected Result**: The Actual Commission value and date should still be there
3. Navigate to the view page
4. **Expected Result**: The data appears correctly in the view

### Test 3: Check Receivables
1. Go to the Receivables page
2. **Expected Result**: A new commission record should appear with:
   - Release Number: `LTO-<record_id>-1`
   - Amount: The value you entered
   - Date: The date you selected

### Test 4: Auto-Fill Checkbox (Superuser/Staff only)
1. In edit mode, check the "Auto-Fill" checkbox in the LTO section
2. **Expected Result**: 
   - Actual Commission field fills with Expected Commission value
   - Date Received field fills with today's date
   - Fields get a blue highlight

### Test 5: Status Updates
1. Set Actual Commission to less than Expected Commission
2. Save
3. **Expected Result**: Status shows "Partial" (yellow badge)
4. Set Actual Commission to equal or greater than Expected Commission
5. Save
6. **Expected Result**: Status shows "Received" (green badge)

## Browser Console Checks

Open browser console (F12) before testing. You should see debug messages like:
```
DEBUG: LTO checkbox checked for tranche <id>
DEBUG: Expected commission: <amount>
DEBUG: Found input field: <input element>
DEBUG: LTO field auto-populated with amount: <amount>, date: <date>
```

## Server Log Checks

Check your Django server logs for these INFO messages:
```
INFO: Processing payment <id> (LTO=True): received_amount="<value>", date_received="<date>"
INFO: Payment <id>: Converted received_amount to Decimal: <value>
INFO: Payment <id>: Set date_received to <date>
INFO: Payment <id>: Set received_amount to <value>
INFO: Payment <id>: Status updated to "<status>", saving payment...
INFO: Payment <id>: Successfully saved with received_amount=<value>, date_received=<date>, status=<status>
INFO: Created new commission for <agent>: LTO-<record_id>-1 - ₱<amount>
```

## Edge Cases to Test

### Edge Case 1: Zero Value
- Enter "0" in Actual Commission
- **Expected**: Should save as 0, status should be "Pending"

### Edge Case 2: Decimal Values
- Enter "12345.67" in Actual Commission
- **Expected**: Should save with 2 decimal places

### Edge Case 3: Large Numbers
- Enter "1000000.50" in Actual Commission
- **Expected**: Should save correctly without overflow

### Edge Case 4: Empty Date
- Enter an Actual Commission value but leave Date empty
- Save
- **Expected**: Date should remain empty (None in database)

### Edge Case 5: Update Existing Record
- Save a value once
- Edit and change the value
- Save again
- **Expected**: Should update (not duplicate) the commission record

## Database Verification (Optional)

If you have database access, run these queries:

### Check TranchePayment table:
```sql
SELECT id, tranche_number, is_lto, received_amount, date_received, status
FROM sparc_tranchepayment
WHERE tranche_record_id = <your_record_id>
AND is_lto = true;
```

### Check Commission table:
```sql
SELECT id, release_number, commission_amount, date_released, agent_id
FROM sparc_commission
WHERE release_number LIKE 'LTO-%';
```

## Troubleshooting

### Issue: Data not saving
- Check browser Network tab for HTTP 500 errors
- Check server logs for error messages
- Verify the form field names match: `received_amount_<payment_id>`

### Issue: Success message but no data
- Check if JavaScript is interfering with form submission
- Verify the main form includes LTO fields (not in a separate form)
- Check if fields are disabled by JavaScript

### Issue: Commission not appearing in Receivables
- Verify the agent name in the tranche matches an active user
- Check server logs for agent lookup warnings
- Verify the user has the correct full name set

## Success Criteria

The fix is working correctly when:
- ✅ LTO Actual Commission saves to database
- ✅ Date Received saves to database
- ✅ Status updates correctly (Pending/Partial/Received)
- ✅ Data persists after page reload
- ✅ Commission record appears in Receivables
- ✅ Auto-fill checkbox works for LTO fields
- ✅ Down Payment Schedule still works correctly
- ✅ No JavaScript errors in console
- ✅ No Python errors in server logs
