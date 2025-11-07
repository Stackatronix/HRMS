import os
from pathlib import Path
import re
import tempfile
from django.core.files.base import ContentFile
from docxtpl import DocxTemplate
from django.conf import settings


def generate_payslip_docx(payroll, template_rel_path="templates/payslip_template.docx"):
    template_path = template_rel_path
    if not os.path.isabs(template_path):
        template_path = os.path.join(settings.BASE_DIR, template_rel_path)
    payroll.is_generating = True
    payroll.save()
    try:
        emp = payroll.employee
        period = payroll.period
        li = payroll.line_items or {}
        company = settings.COMPANY_CONFIG.get("organization", {}).get("name", "MyCompany")
        company_address = settings.COMPANY_CONFIG.get("organization", {}).get(
            "address", "123 Business St, City, Country"
        )
        company_contact = settings.COMPANY_CONFIG.get("organization", {}).get(
            "email", "contact@mycompany.com"
        )

        context = {
            "company": company,
            "company_address": company_address,
            "company_contact": company_contact,
            "employee_name": emp.fullname,
            "email": getattr(emp.user, "email", "") if emp.user else "",
            "designation": emp.designation,
            "department": getattr(emp.department, "name", ""),
            "period": f"{period.start} to {period.end}",
            "base_earned": li.get("base_salary", "0.00"),
            "overtime_pay": li.get("overtime_pay", "0.00"),
            "deductions": li.get("deductions", "0.00"),
            "gross": str(payroll.gross),
            "net": str(payroll.net),
            "currency": payroll.currency,
            "bank_account": emp.bank_account or "N/A",
            "ifsc": emp.ifsc_code or "N/A",
        }

        
        doc = DocxTemplate(template_path)
        doc_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".docx")
        doc.render(context)
        doc.save(doc_tmp.name)

        with open(doc_tmp.name, "rb") as fp:
            content = ContentFile(fp.read())
        safe_name = re.sub(r'[^\w\s-]', '', emp.fullname).strip().replace(' ', '_')
        filename = f"payslip_{safe_name}_{period.start}_{period.end}.docx"
        file_path = Path(settings.MEDIA_ROOT) / "payslips" / filename
        try:
            os.remove(file_path)
        except FileNotFoundError:
            pass
        payroll.payslip_file.save(filename, content, save=True)
    except Exception as e:
        raise e
    finally:
        payroll.is_generating = False
        payroll.save()
        try:
            os.unlink(doc_tmp.name)
        except Exception:
            pass

    return payroll.payslip_file.name
