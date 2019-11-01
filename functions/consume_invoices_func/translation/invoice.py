import re
import dateutil.parser

from calendar import monthrange
from datetime import date


def enrichdata(jsonw):
    note(jsonw['Data'])
    taxshift(jsonw['Data'])
    totaltax(jsonw['Data'])
    totalamount(jsonw['Data'])
    invoicetype(jsonw['Data'])
    compcodefin(jsonw['Data'])
    vendorID(jsonw['Data'])
    paymentagreementdate(jsonw['Data'])
    scandate(jsonw['Data'])
    scantiff(jsonw)
    additionalcoding(jsonw['Data'])


# Checks if it's noted that tax is shifted
def note(jsonw):
    checkstring = jsonw['NoteTax'].lower().replace(" ", "")
    if 'btwverlegd' in checkstring:
        return True
    elif 'verlegdbtw' in checkstring:
        return True
    else:
        return False


# Determines if tax is shifted according to UNCL5305 standards
def taxshift(jsonw):
    checkvalue = jsonw['taxshiftedTotalTax'].upper()
    if 'AE' in checkvalue or 'G' in checkvalue:
        jsonw['percentquantityTotalTax'] = '21.00'
        jsonw['taxshiftedTotalTax'] = True
    elif 'E' in checkvalue or 'Z' in checkvalue:
        jsonw['percentquantityTotalTax'] = '0.00'
        jsonw['taxshiftedTotalTax'] = False
    else:
        jsonw['taxshiftedTotalTax'] = False


# Checks if Tax amount is accurate according to percentage
def totaltax(jsonw):
    if float(jsonw['TotalTax']) != float(jsonw['percentquantityTotalTax']) * (float(jsonw['TotalCharges']) / 100):
        print(False)


# Checks if Total amount is accurate according to tax
def totalamount(jsonw):
    pct = float(jsonw['percentquantityTotalTax']) / 100 + 1

    if float(jsonw['TotalAmount']) != pct*float(jsonw['TotalCharges']):
        print(False)


# Determines if it's a credit or debit invoice
def invoicetype(jsonw):
    if float(jsonw['TotalAmount']) < 0:
        jsonw['InvoiceType'] = 'Credit'
    else:
        jsonw['InvoiceType'] = 'Debit'


# Extracts the VWT company code from ordernumber +
def compcodefin(jsonw):
    if re.findall('[0-9]{3}-[0-9]{6}', jsonw['OrderNumber']):
        list = re.findall('[0-9]{3}-[0-9]{6}', jsonw['OrderNumber'])
        jsonw['OrderNumber'] = list[0]
        jsonw['CompCodeFin'] = list[0][:3]
    elif re.findall('[0-9]{6}', jsonw['OrderNumber']):
        list = re.findall('[0-9]{3}-[0-9]{6}', jsonw['OrderNumber'])
        jsonw['OrderNumber'] = list[0][:3] + '-' + list[4:]
        jsonw['CompCodeFin'] = list[0][:3]
    else:
        print("Order Number not recognized")


# Link to VBS
def vendorID(jsonw):
    print('no link VBS')


# Extracts first and last of month from invoicedate
def paymentagreementdate(jsonw):

    date = dateutil.parser.parse(jsonw['InvoiceDate'])
    monthdate = monthrange(date.year, date.month)

    jsonw['PaymentAgreementDateFrom'] = str(date.year) + '-' + '%02d' % date.month + '-' + '01'
    jsonw['PaymentAgreementDateTo'] = str(date.year) + '-' + '%02d' % date.month + '-' + str(monthdate[1])


# Date of handling invoice
def scandate(jsonw):
    jsonw['ScanDate'] = str(date.today())


# Name of corresponding PDF
def scantiff(jsonw):
    newname = jsonw['Meta']['fileName'][:-3] + "pdf"
    jsonw['Data']['ScanTIFF'] = newname


# Extra check VendorID
def additionalcoding(jsonw):
    jsonw['AdditionalCoding'] = 'No'
