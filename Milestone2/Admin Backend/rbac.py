"""Role-based access control for FreightQuote AI (FastAPI backend)."""
ADMIN="Admin"; OPS="Operations Manager"; BROKER="Freight Broker"; AUDITOR="Auditor"; CUSTOMER="Customer"
ROLES=(ADMIN,OPS,BROKER,AUDITOR,CUSTOMER)
ROLE_MENU={
 ADMIN:{"copilot","route","quotes","carriers","weather","margin","customs","admin","profile"},
 OPS:{"copilot","route","carriers","weather","customs","profile"},
 BROKER:{"copilot","quotes","carriers","margin","profile"},
 AUDITOR:{"copilot","route","quotes","carriers","weather","margin","customs","profile"},
 CUSTOMER:{"copilot","quotes","profile"},
}
ROLE_CAPS={
 ADMIN:{"users","quote","run","approve","resolve","admin","storm"},
 OPS:{"run","approve","resolve"},
 BROKER:{"quote"},
 AUDITOR:set(),
 CUSTOMER:{"quote_own"},
}
MENU_ORDER=("copilot","route","quotes","carriers","weather","margin","customs","admin","profile")
MENU_LABELS={
 "copilot":("AI Copilot","bot"),"route":("Agent 1 · Route AI","route"),
 "quotes":("Agent 2 · Spot Quotes","dollar"),"carriers":("Agent 3 · Carriers","truck"),
 "weather":("Agent 4 · Weather Risk","cloud"),"margin":("Agent 5 · Margin","trend"),
 "customs":("Agent 6 · Customs","file"),"admin":("Admin dashboard","users"),
 "profile":("My profile","user"),
}
def can_page(role,page):
 return role in ROLES and (page=="profile" or page in ROLE_MENU.get(role,set()))
def can_do(role,cap):
 if role==ADMIN:return True
 if cap=="view":return role in ROLES
 if cap=="quote" and role==CUSTOMER:return False
 return cap in ROLE_CAPS.get(role,set())
def menu_for(role):
 return [{"id":p,"label":MENU_LABELS[p][0],"icon":MENU_LABELS[p][1]} for p in MENU_ORDER if can_page(role,p)]
def need(role,cap):
 if not can_do(role,cap):
  raise PermissionError(f"403 - the {role or 'unknown'} role cannot perform '{cap}'.")
 return True
