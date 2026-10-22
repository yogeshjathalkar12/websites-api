"""raptor/audit/funnel.py: "Leaks in the funnel": can a visitor reach the company, and can the company see who visited?

Read from the home page and up to three contact-type pages, exactly as served (no scripts are run on this server). Presence is a measured fact.
Absence only counts against the company when the page can be read reliably: if the site builds its pages with scripts (js_heavy), or loads its
tags through a tag manager, the result is `unknown`, because a plain read cannot see what a browser would.
"""
from __future__ import annotations

import re

from .common import check, unknown

S = "funnel"

CHAT = {"Tawk.to": "tawk.to", "Intercom": "intercom", "Drift": "drift.com", "Crisp": "crisp.chat", "Tidio": "tidio", "HubSpot chat": "js.usemessages.com", "Zendesk chat": "zopim|zdassets",
        "LiveChat": "livechatinc", "Zoho SalesIQ": "salesiq.zoho", "WATI": "wati.io", "Gupshup": "gupshup", "Freshchat": "freshchat", "Smartsupp": "smartsupp", "JivoChat": "jivosite"}
ANALYTICS = {"Google Analytics": r"googletagmanager\.com/gtag/js|google-analytics\.com/(analytics|ga)\.js|gtag\(\s*['\"]config['\"]", "Meta (Facebook) Pixel": r"connect\.facebook\.net/[^'\"]*fbevents\.js|fbq\(\s*['\"]init",
             "LinkedIn Insight Tag": r"snap\.licdn\.com|_linkedin_partner_id", "Microsoft Clarity": r"clarity\.ms", "Hotjar": r"static\.hotjar\.com|hotjar\.com", "Plausible": r"plausible\.io/js",
             "Matomo": r"matomo|piwik", "Google Ads": r"googleadservices\.com|AW-\d{6,}", "TikTok Pixel": r"analytics\.tiktok\.com"}
TAG_MANAGER = r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]{4,}"
CRM_TAGS = {"HubSpot": r"js\.hs-scripts\.com|js\.hsforms\.net|hubspot\.com/embed", "Zoho": r"zohopublic|salesiq\.zoho|zoho\.com/crm|forms\.zohopublic", "Salesforce / Pardot": r"pardot\.com|salesforce\.com/servlet|force\.com",
            "Freshworks": r"freshsales|freshworks\.com|freshdesk", "Pipedrive": r"pipedrive\.com|leadbooster", "Mailchimp": r"chimpstatic\.com|list-manage\.com", "Zendesk": r"zendesk\.com"}
BOOKING = r"calendly\.com|cal\.com|savvycal|hubspot\.com/meetings|tidycal|zohobookings|setmore\.com|youcanbook\.me"
WHATSAPP = re.compile(r"(wa\.me/|api\.whatsapp\.com/send|web\.whatsapp\.com/send|whatsapp://send|wa\.link/)", re.I)


def _blob(pages: dict) -> str:
    parts = []
    for pg in pages.values():
        parts.append(pg.script_blob)
        parts.append("\n".join(f["action"] for f in pg.forms))
        parts.append("\n".join(pg.iframes))
        parts.append("\n".join(l["href"] for l in pg.links))
    return "\n".join(parts)


def _classify(form: dict) -> str:
    """'contact' (a message or an enquiry), 'signup' (one email box, e.g. a newsletter), 'search' or 'other'."""
    names = " ".join(i["name"] for i in form["inputs"])
    kinds = [i["type"] for i in form["inputs"]]
    if "search" in kinds or re.search(r"\bq\b|search|query", names) and len(form["inputs"]) <= 1 and not form["textarea"]:
        return "search"
    if "password" in kinds:
        return "login"
    if form["textarea"] or (len(form["inputs"]) >= 2 and any(k in kinds for k in ("email", "tel"))) or re.search(r"message|enquiry|inquiry|phone|mobile|company", names):
        return "contact"
    if "email" in kinds or "email" in names:
        return "signup"
    return "other"


def run(ctx):
    out = []
    if not ctx.page:
        why = (ctx.refused_reason + ", so this was not checked. We did not try to get around that.") if ctx.refused else "The home page could not be read, so this was not checked."
        for cid, title in (("contact_path", "A way to contact the company"), ("contact_form", "Enquiry form"), ("analytics", "Visitor tracking")):
            out.append(unknown(cid, S, title, why))
        return out
    pages = ctx.pages
    n_pages = len(pages)
    scope = "%d page(s) read: the home page%s." % (n_pages, " and " + str(n_pages - 1) + " contact-type page(s)" if n_pages > 1 else "")
    gap = scope + " Anything a script adds after the page loads cannot be seen by a plain read, so check the page in a browser before presenting this."
    heavy = ctx.page.js_heavy
    heavy_note = "This site builds its pages with scripts, so a plain read cannot see everything a visitor sees."
    blob = _blob(pages)
    links = [l["href"] for pg in pages.values() for l in pg.links]

    forms = [f for pg in pages.values() for f in pg.forms]
    kinds = [_classify(f) for f in forms]
    contact_forms = kinds.count("contact")
    signup_forms = kinds.count("signup")
    tel = [h for h in links if h.lower().startswith("tel:")]
    mail = [h for h in links if h.lower().startswith("mailto:")]
    wa = [h for h in links if WHATSAPP.search(h)] + (["widget"] if WHATSAPP.search(blob) else [])
    booking = re.search(BOOKING, blob + "\n" + "\n".join(links), re.I)
    chat = [name for name, pat in CHAT.items() if re.search(pat, blob, re.I)]
    reachable = bool(contact_forms or tel or mail or wa or booking or chat)

    # any way at all
    if reachable:
        ways = [w for w, ok in (("enquiry form", contact_forms), ("click-to-call link", tel), ("email link", mail), ("WhatsApp button", wa), ("booking link", booking), ("chat widget (%s)" % ", ".join(chat), chat)) if ok]
        out.append(check("contact_path", S, "A way to contact the company", "pass", value=", ".join(ways), weight=3, priority=14, detail=scope, source="Forms, links and scripts on the pages we read"))
    elif heavy:
        out.append(unknown("contact_path", S, "A way to contact the company", heavy_note + " " + scope))
    else:
        out.append(check("contact_path", S, "A way to contact the company", "issue", value="none found", weight=3, priority=14,
                         detail="No enquiry form, phone link, email link, WhatsApp button, booking link or chat widget was found. " + gap, source="Forms, links and scripts on the pages we read",
                         verify="Open the site on a phone and look for a way to contact them without leaving the page.", fix="Add a visible enquiry form and a click-to-call or WhatsApp button on every page.",
                         raptor="Raptor's CRM captures every enquiry and follows up by email, WhatsApp and SMS automatically."))

    # enquiry form
    if contact_forms:
        out.append(check("contact_form", S, "Enquiry form", "pass", value="%d form(s) that take a message" % contact_forms, priority=15, source="<form> elements on the pages we read", detail=scope))
    elif heavy:
        out.append(unknown("contact_form", S, "Enquiry form", heavy_note))
    elif reachable and not forms:
        out.append(check("contact_form", S, "Enquiry form", "warn", value="none", priority=15, detail="Visitors can reach the company, but not by leaving details in a form they can fill in at any hour. " + gap,
                         source="<form> elements on the pages we read", fix="Add a short enquiry form (name, phone or email, message) on the home page."))
    elif not reachable:
        pass            # already reported under 'a way to contact'
    else:
        out.append(check("contact_form", S, "Enquiry form", "warn", value="none that takes a message", priority=15, detail="Forms found, but none that lets a visitor send an enquiry. " + gap, source="<form> elements on the pages we read",
                         fix="Add a short enquiry form on the home page."))

    # click to call / whatsapp
    if tel:
        out.append(check("click_to_call", S, "Click-to-call", "pass", value=tel[0][4:].split("?")[0], priority=16, source="tel: links on the pages we read"))
    elif not heavy:
        out.append(check("click_to_call", S, "Click-to-call", "warn", value="no tel: link", priority=16,
                         detail="No phone number that a visitor on a mobile can tap to call (a number shown as plain text cannot be tapped). " + gap, source="tel: links on the pages we read", fix="Make the phone number a tel: link."))
    if wa:
        out.append(check("whatsapp_button", S, "WhatsApp contact", "pass", value="present", priority=17, source="Links and scripts on the pages we read"))
    elif not heavy:
        out.append(check("whatsapp_button", S, "WhatsApp contact", "warn", value="none found", priority=17,
                         detail="No WhatsApp link or button was found. In India many customers prefer to message first. " + gap, source="Links and scripts on the pages we read",
                         fix="Add a WhatsApp click-to-chat button.", raptor="Raptor connects WhatsApp to the CRM so replies are logged and followed up."))

    # lead capture
    if signup_forms or contact_forms:
        out.append(check("lead_capture", S, "Captures visitor details", "pass", value="%d contact form(s), %d sign-up form(s)" % (contact_forms, signup_forms), priority=18, source="<form> elements on the pages we read"))
    elif not heavy:
        out.append(check("lead_capture", S, "Captures visitor details", "warn", value="no form found", priority=18,
                         detail="Nothing on the pages we read lets a visitor leave their email or phone, so people who are not ready to buy today are lost. " + gap, source="<form> elements on the pages we read",
                         fix="Offer something useful (a guide, a quote, a callback) in exchange for an email or phone number."))

    # analytics / pixel / CRM
    found_analytics = [name for name, pat in ANALYTICS.items() if re.search(pat, blob, re.I)]
    gtm = bool(re.search(TAG_MANAGER, blob))
    if found_analytics:
        out.append(check("analytics", S, "Visitor tracking", "pass", value=", ".join(found_analytics), weight=2, priority=19, source="Scripts loaded by the pages we read",
                         verify="View Source and search for the script names, or use a tag-detector browser extension."))
    elif gtm:
        out.append(check("analytics", S, "Visitor tracking", "info", value="Google Tag Manager present", priority=19,
                         detail="The site uses Google Tag Manager, which loads its tags inside the container, so a plain read cannot list them (they may well include analytics).", source="Scripts loaded by the pages we read"))
    elif heavy:
        out.append(unknown("analytics", S, "Visitor tracking", heavy_note))
    else:
        out.append(check("analytics", S, "Visitor tracking", "issue", value="none detected", weight=2, priority=19,
                         detail="No analytics or ad pixel was found in the pages as served, so the company probably cannot see how many visitors it gets or which ones came from ads. Tags added later by a script would not show here.",
                         source="Scripts loaded by the pages we read", verify="View Source and search for gtag, fbq or analytics.", fix="Install Google Analytics, and a Meta or LinkedIn pixel if you advertise."))

    crm = [name for name, pat in CRM_TAGS.items() if re.search(pat, blob, re.I)]
    out.append(check("crm_tag", S, "CRM or marketing tools connected", "info", value=", ".join(crm) if crm else "none detected", priority=85,
                     detail="" if crm else "None of the common CRM or email-marketing embeds were found in the pages as served. A CRM can also be connected in ways a web page does not show.", source="Scripts and embeds on the pages we read"))
    if chat:
        out.append(check("chat_widget", S, "Live chat", "info", value=", ".join(chat), priority=86, source="Scripts loaded by the pages we read"))
    if booking:
        out.append(check("booking_link", S, "Online booking", "info", value=booking.group(0), priority=87, source="Links and embeds on the pages we read"))
    return out
