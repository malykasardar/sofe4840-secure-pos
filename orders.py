"""
orders.py
Owner: Mohammad Al-Lozy (100829387)
"""

from flask import Blueprint, request, session, redirect, render_template, abort, flash
from datetime import datetime
import uuid
import json

import database as db
import crypto
from auth import require_role

orders_bp = Blueprint("orders", __name__)


# ---------------------------------------------------------------------------
# Purchaser
# ---------------------------------------------------------------------------

@orders_bp.route("/order/create", methods=["POST"])
@require_role("purchaser")
def create_order():
    import re

    raw_items       = request.form.get("items", "").strip()
    raw_quantity    = request.form.get("quantity", "").strip()
    raw_unit_price  = request.form.get("unit_price", "").strip()
    raw_vendor      = request.form.get("vendor", "").strip()
    raw_justification = request.form.get("justification", "").strip()

    errors = []

    # Whitelist validation - Lec09: input should be compared against what is wanted
    # Item description: printable text only, 1-200 chars
    if not raw_items or len(raw_items) > 200:
        errors.append("Item description must be between 1 and 200 characters.")
    if not re.match(r'^[\w\s\-\.,/()]+$', raw_items):
        errors.append("Item description contains invalid characters.")

    # Quantity: positive integer only
    try:
        quantity = int(raw_quantity)
        if quantity <= 0 or quantity > 10000:
            errors.append("Quantity must be a positive integer no greater than 10,000.")
    except ValueError:
        errors.append("Quantity must be a whole number.")
        quantity = None

    # Unit price: positive number with up to 2 decimal places
    try:
        unit_price = float(raw_unit_price)
        if unit_price <= 0 or unit_price > 1_000_000:
            errors.append("Unit price must be a positive number no greater than $1,000,000.")
    except ValueError:
        errors.append("Unit price must be a valid number.")
        unit_price = None

    # Vendor: printable text, 1-100 chars
    if not raw_vendor or len(raw_vendor) > 100:
        errors.append("Vendor name must be between 1 and 100 characters.")
    if not re.match(r'^[\w\s\-\.,/()&]+$', raw_vendor):
        errors.append("Vendor name contains invalid characters.")

    # Justification: text only, 10-1000 chars
    if len(raw_justification) < 10 or len(raw_justification) > 1000:
        errors.append("Justification must be between 10 and 1,000 characters.")

    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect("/dashboard/purchaser")

    supervisor = db.get_supervisor()
    if not supervisor:
        flash("No supervisor registered yet. Ask a supervisor to register first.", "danger")
        return redirect("/dashboard/purchaser")

    order_data = {
        "order_uid":        str(uuid.uuid4()),
        "item_description": raw_items,
        "quantity":         str(quantity),
        "unit_price":       f"{unit_price:.2f}",
        "vendor":           raw_vendor,
        "justification":    raw_justification,
    }

    timestamp  = datetime.utcnow().isoformat()
    order_hash = crypto.hash_order(order_data, timestamp)
    signature  = crypto.sign_data(session["decrypted_private_key"], order_hash, timestamp)
    encrypted  = crypto.encrypt_for_recipient(supervisor["public_key"], json.dumps(order_data))

    db.insert_order(
        order_uid           = order_data["order_uid"],
        purchaser_id        = session["user_id"],
        supervisor_id       = supervisor["id"],
        encrypted_payload   = encrypted,
        purchaser_signature = signature,
        purchaser_timestamp = timestamp,
        status              = "pending",
        created_at          = timestamp,
        order_meta          = json.dumps(order_data),
    )
    db.write_audit_log(session["user_id"], "order_created", order_data["order_uid"])
    flash("Order submitted successfully.", "success")
    return redirect("/dashboard/purchaser")


@orders_bp.route("/dashboard/purchaser")
@require_role("purchaser")
def purchaser_dashboard():
    raw_orders = db.get_orders_by_purchaser(session["user_id"])
    orders = []
    for o in raw_orders:
        o = dict(o)
        # Use stored metadata - purchaser always sees their own order details
        # regardless of what stage the encrypted payload is at
        if o.get("order_meta"):
            try:
                meta = json.loads(o["order_meta"])
                o["item_description"] = meta.get("item_description", "(unknown)")
                o["vendor"]           = meta.get("vendor", "(unknown)")
                o["quantity"]         = meta.get("quantity", "-")
                o["unit_price"]       = meta.get("unit_price", "-")
                o["justification"]    = meta.get("justification", "")
            except Exception:
                o["item_description"] = "(error)"
                o["vendor"] = "(error)"
        else:
            o["item_description"] = "(encrypted)"
            o["vendor"] = "(encrypted)"
            o["quantity"] = "-"
            o["unit_price"] = "-"
        orders.append(o)
    return render_template("purchaser_dashboard.html", orders=orders)


# ---------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------

@orders_bp.route("/order/<int:order_id>/approve", methods=["POST"])
@require_role("supervisor")
def approve_order(order_id):
    order = db.get_order(order_id)
    if not order:
        abort(404)
    if order["status"] != "pending":
        flash("Order is no longer pending.", "warning")
        return redirect("/dashboard/supervisor")
    if order["supervisor_id"] != session["user_id"]:
        abort(403)

    # 1. Decrypt payload
    try:
        plaintext  = crypto.decrypt_payload(session["decrypted_private_key"], order["encrypted_payload"])
        order_data = json.loads(plaintext)
    except Exception:
        flash("Failed to decrypt order.", "danger")
        return redirect("/dashboard/supervisor")

    # 2. Verify purchaser signature
    purchaser  = db.get_user_by_id(order["purchaser_id"])
    order_hash = crypto.hash_order(order_data, order["purchaser_timestamp"])
    valid = crypto.verify_signature(
        purchaser["public_key"],
        order["purchaser_signature"],
        order_hash,
        order["purchaser_timestamp"]
    )
    if not valid:
        flash("Purchaser signature verification failed. Order may have been tampered with.", "danger")
        db.write_audit_log(session["user_id"], "signature_verification_failed", order_id)
        return redirect("/dashboard/supervisor")

    # 3. Supervisor co-signs
    sup_timestamp = datetime.utcnow().isoformat()
    sup_signature = crypto.sign_data(session["decrypted_private_key"], order_hash, sup_timestamp)

    # 4. Re-encrypt for orders department
    orders_dept = db.get_orders_dept_user()
    if not orders_dept:
        flash("No orders department user registered yet.", "danger")
        return redirect("/dashboard/supervisor")

    re_encrypted = crypto.encrypt_for_recipient(orders_dept["public_key"], plaintext)

    # 5. Update DB
    db.update_order(
        order_id,
        status               = "approved",
        encrypted_payload    = re_encrypted,
        supervisor_signature = sup_signature,
        supervisor_timestamp = sup_timestamp,
    )
    db.write_audit_log(session["user_id"], "order_approved", order_id)
    flash("Order approved and forwarded to orders department.", "success")
    return redirect("/dashboard/supervisor")


@orders_bp.route("/order/<int:order_id>/reject", methods=["POST"])
@require_role("supervisor")
def reject_order(order_id):
    order = db.get_order(order_id)
    if not order:
        abort(404)
    if order["status"] != "pending":
        flash("Order is no longer pending.", "warning")
        return redirect("/dashboard/supervisor")
    if order["supervisor_id"] != session["user_id"]:
        abort(403)

    db.update_order(order_id, status="rejected")
    db.write_audit_log(session["user_id"], "order_rejected", order_id)
    flash("Order rejected.", "info")
    return redirect("/dashboard/supervisor")


@orders_bp.route("/dashboard/supervisor")
@require_role("supervisor")
def supervisor_dashboard():
    raw_orders = db.get_orders_by_supervisor(session["user_id"])
    orders = []
    for o in raw_orders:
        o = dict(o)
        try:
            payload = json.loads(crypto.decrypt_payload(session["decrypted_private_key"], o["encrypted_payload"]))
            o.update(payload)
            purchaser = db.get_user_by_id(o["purchaser_id"])
            o["purchaser_name"] = purchaser["username"] if purchaser else "Unknown"
        except Exception:
            o["purchaser_name"] = "Unknown"
        orders.append(o)
    return render_template("supervisor_dashboard.html", orders=orders)


# ---------------------------------------------------------------------------
# Orders department
# ---------------------------------------------------------------------------

@orders_bp.route("/order/<int:order_id>/process", methods=["POST"])
@require_role("orders_dept")
def process_order(order_id):
    order = db.get_order(order_id)
    if not order:
        abort(404)
    if order["status"] != "approved":
        flash("Order is not in approved state.", "warning")
        return redirect("/dashboard/orders")

    # 1. Decrypt payload
    try:
        plaintext  = crypto.decrypt_payload(session["decrypted_private_key"], order["encrypted_payload"])
        order_data = json.loads(plaintext)
    except Exception:
        flash("Failed to decrypt order.", "danger")
        return redirect("/dashboard/orders")

    order_hash = crypto.hash_order(order_data, order["purchaser_timestamp"])

    # 2. Verify purchaser signature
    purchaser = db.get_user_by_id(order["purchaser_id"])
    if not purchaser:
        flash("Purchaser account no longer exists. Cannot verify signature.", "danger")
        return redirect("/dashboard/orders")
    p_valid = crypto.verify_signature(
        purchaser["public_key"],
        order["purchaser_signature"],
        order_hash,
        order["purchaser_timestamp"]
    )

    # 3. Verify supervisor signature
    supervisor = db.get_user_by_id(order["supervisor_id"])
    if not supervisor:
        flash("Supervisor account no longer exists. Cannot verify signature.", "danger")
        return redirect("/dashboard/orders")
    s_valid = crypto.verify_signature(
        supervisor["public_key"],
        order["supervisor_signature"],
        order_hash,
        order["supervisor_timestamp"]
    )

    if not p_valid or not s_valid:
        flash("Signature verification failed. Cannot process order.", "danger")
        db.write_audit_log(session["user_id"], "signature_verification_failed", order_id)
        return redirect("/dashboard/orders")

    db.update_order(order_id, status="processed")
    db.write_audit_log(session["user_id"], "order_processed", order_id)
    flash("Order processed successfully.", "success")
    return redirect("/dashboard/orders")


@orders_bp.route("/dashboard/orders")
@require_role("orders_dept")
def orders_dashboard():
    raw_orders = db.get_approved_orders()
    orders = []
    for o in raw_orders:
        o = dict(o)
        try:
            plaintext  = crypto.decrypt_payload(session["decrypted_private_key"], o["encrypted_payload"])
            order_data = json.loads(plaintext)
            o.update(order_data)

            order_hash = crypto.hash_order(order_data, o["purchaser_timestamp"])

            purchaser  = db.get_user_by_id(o["purchaser_id"])
            supervisor = db.get_user_by_id(o["supervisor_id"])

            o["purchaser_name"]  = purchaser["username"] if purchaser else "Unknown"
            o["supervisor_name"] = supervisor["username"] if supervisor else "Unknown"
            o["purchaser_sig_valid"] = crypto.verify_signature(
                purchaser["public_key"], o["purchaser_signature"],
                order_hash, o["purchaser_timestamp"]
            ) if purchaser else False
            o["supervisor_sig_valid"] = crypto.verify_signature(
                supervisor["public_key"], o["supervisor_signature"],
                order_hash, o["supervisor_timestamp"]
            ) if supervisor else False
        except Exception:
            o["purchaser_sig_valid"]  = False
            o["supervisor_sig_valid"] = False
        orders.append(o)
    return render_template("orders_dashboard.html", orders=orders)
