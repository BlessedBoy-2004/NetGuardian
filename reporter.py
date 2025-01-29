from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import sqlite3

def generate_report():
    """Generate professional PDF report from threats database"""
    doc = SimpleDocTemplate("security_report.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph("<b>NetGuardian Security Report</b>", styles['Title']))
    story.append(Spacer(1, 12))

    # Connect to database
    conn = sqlite3.connect('threats.db')
    c = conn.cursor()

    # Threat Summary
    c.execute("SELECT COUNT(*), tactic_id FROM threats GROUP BY tactic_id")
    results = c.fetchall()
    
    for count, tactic_id in results:
        story.append(Paragraph(
            f"• <b>Tactic {tactic_id}</b>: {count} incidents", 
            styles['BodyText']
        ))
    
    # MITRE ATT&CK Details
    story.append(Spacer(1, 24))
    story.append(Paragraph("<b>MITRE ATT&CK Techniques Detected:</b>", styles['Heading2']))
    
    c.execute("SELECT DISTINCT technique_id FROM threats")
    for (technique_id,) in c.fetchall():
        story.append(Paragraph(f"- Technique ID: {technique_id}", styles['BodyText']))

    conn.close()
    doc.build(story)

if __name__ == "__main__":
    generate_report()
    print("✅ Report generated: security_report.pdf")