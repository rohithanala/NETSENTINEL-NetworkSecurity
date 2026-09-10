from flask import Blueprint,render_template
pages=Blueprint("pages",__name__)
@pages.get("/")
def home():return render_template("dashboard.html")
@pages.get("/<page>")
def page(page):
 allowed={"dashboard","live-traffic","alerts","network","analytics","settings"}
 if page not in allowed:return ("Not Found",404)
 return render_template(page.replace("-","_")+".html" if page!="dashboard" else "dashboard.html")
