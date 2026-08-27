//! SCIM mirroring: an IdP's org chart, materialised as a key hierarchy.
//!
//! The fleet is **not** the source of truth here. Okta or Entra is, and this
//! mirrors what it pushes. That is the honest shape: nobody rips out their
//! directory, and a control plane that demanded to own identity would never be
//! deployed. What it adds is the half SCIM cannot do.
//!
//! ## What SCIM gives, and what it does not
//!
//! When an IdP deactivates a user it sends `active: false`. That is advisory —
//! a flag in a directory that every downstream app has to be trusted to honour.
//! Sessions already issued survive it, tokens survive it, and an app that never
//! processed the change simply keeps working.
//!
//! Here, `active: false` **burns the seat**. The index is consumed out of the
//! allocator, so the next person into that seat derives a different key and the
//! departing holder's position is never reissued. The operator still has to spend
//! their capability grants to remove access that already exists — burning governs
//! who comes next, not who is already in the field — but the position itself is
//! retired cryptographically rather than by a boolean somebody has to respect.
//!
//! Reactivation therefore gives a person a NEW seat, not their old one back.
//! SCIM has no opinion on this; it is provider-defined. Returning the old index
//! would mean un-retiring a burned one, which is the whole thing the burn exists
//! to prevent.
//!
//! ## Mapping
//!
//!   SCIM Group  ->  a zone      `deriveChild(root, "zone", ...)`
//!   SCIM User   ->  a member    `deriveChild(zone, "member", ...)`
//!   externalId  ->  the stable handle a position is remembered by
//!
//! `externalId` is the IdP's own immutable identifier, and it is what the
//! mapping is keyed on — never `userName`, which people change when they marry.
//! A rename must not move anyone's key.
//!
//! ## Idempotency
//!
//! SCIM clients retry, and a retried create must not allocate a second index.
//! Every operation here is keyed on `externalId` and is safe to replay: the same
//! create returns the same position, and a repeated deactivate does not burn
//! twice.

const std = @import("std");
const identity = @import("identity");
const store_mod = @import("store");
const Store = store_mod.Store;
const domains = @import("domains");

pub const Error = error{
    UnknownExternalId,
    MissingExternalId,
    ZoneNotFound,
};

pub const zone_resource = "zone";
pub const member_resource = "member";

/// The two domains this mirror derives into.
///
/// These were both `CHILD_CREATION` (0x06) until the namespace split. That was
/// wrong in a way arithmetic hid: the allocator is keyed on the whole
/// `(parent, resourceId, domainFlag)` tuple, so people and devices never
/// collided on an index — but they were the SAME domain to every layer below
/// this one. A cell minted for a person carried the same header flag as one
/// minted for a device, so `OP_CHECKDOMAINFLAG` could not tell them apart, the
/// schema registry could not key them apart, and a Plexus enrolment recorded
/// one context where there are two.
pub const zone_flag: u64 = domains.zone;
pub const member_flag: u64 = domains.org_member;

/// What a mirrored operation did. Returned so a caller can log the truth rather
/// than assuming — a retried create and a first create are not the same event.
pub const Outcome = enum {
    created,
    unchanged,
    reactivated_new_seat,
    deactivated_seat_burned,
    already_inactive,
};

pub const Seat = struct {
    external_id: []const u8,
    zone_external_id: []const u8,
    cert_id: [64]u8,
    public_key_hex: [66]u8,
    derivation_path: []const u8,
    child_index: u64,
    active: bool,

    pub fn deinit(self: Seat, allocator: std.mem.Allocator) void {
        allocator.free(self.external_id);
        allocator.free(self.zone_external_id);
        allocator.free(self.derivation_path);
    }
};

pub const Zone = struct {
    external_id: []const u8,
    cert_id: [64]u8,
    derivation_path: []const u8,
    child_index: u64,

    pub fn deinit(self: Zone, allocator: std.mem.Allocator) void {
        allocator.free(self.external_id);
        allocator.free(self.derivation_path);
    }
};

/// The mirror: an IdP's directory projected onto a derivation tree.
pub const Mirror = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    email: []const u8,
    salt: []const u8,
    root_cert_id: [64]u8,
    /// externalId -> zone
    zones: std.StringHashMap(Zone),
    /// externalId -> seat (the CURRENT seat; a burned one is not kept here)
    seats: std.StringHashMap(Seat),

    pub fn init(
        allocator: std.mem.Allocator,
        store: *Store,
        email: []const u8,
        salt: []const u8,
    ) !Mirror {
        const root = try identity.rootIdentity(allocator, email, salt);
        return .{
            .allocator = allocator,
            .store = store,
            .email = email,
            .salt = salt,
            .root_cert_id = root.cert_id,
            .zones = std.StringHashMap(Zone).init(allocator),
            .seats = std.StringHashMap(Seat).init(allocator),
        };
    }

    pub fn deinit(self: *Mirror) void {
        var zi = self.zones.valueIterator();
        while (zi.next()) |z| z.deinit(self.allocator);
        self.zones.deinit();
        var si = self.seats.valueIterator();
        while (si.next()) |s| s.deinit(self.allocator);
        self.seats.deinit();
    }

    /// Mirror a SCIM Group. Idempotent on `external_id`.
    pub fn putZone(self: *Mirror, external_id: []const u8, display_name: []const u8) !Zone {
        if (self.zones.get(external_id)) |z| return z;

        const index = try self.store.allocateIndex(&self.root_cert_id, zone_resource, zone_flag);
        const node = try identity.deriveChildIdentity(
            self.allocator,
            self.email,
            self.salt,
            "root",
            zone_resource,
            zone_flag,
            index,
        );
        errdefer node.deinit(self.allocator);

        try self.store.putNode(.{
            .cert_id = &node.cert_id,
            .parent_cert_id = &self.root_cert_id,
            .resource_id = zone_resource,
            .domain_flag = zone_flag,
            .child_index = index,
            .label = display_name,
        });

        const owned_ext = try self.allocator.dupe(u8, external_id);
        const zone = Zone{
            .external_id = owned_ext,
            .cert_id = node.cert_id,
            .derivation_path = node.derivation_path, // ownership moves to Zone
            .child_index = index,
        };
        self.allocator.free(node.invoice_number);
        try self.zones.put(owned_ext, zone);
        return zone;
    }

    /// Mirror a SCIM User.
    ///
    /// Keyed on `external_id`, never `user_name` — a rename must not move
    /// anyone's key. Safe to replay: a repeated create returns the same seat.
    pub fn putUser(
        self: *Mirror,
        external_id: []const u8,
        zone_external_id: []const u8,
        display_name: []const u8,
        active: bool,
    ) !struct { seat: ?Seat, outcome: Outcome } {
        if (external_id.len == 0) return Error.MissingExternalId;
        const zone = self.zones.get(zone_external_id) orelse return Error.ZoneNotFound;

        if (self.seats.get(external_id)) |existing| {
            if (existing.active and active) return .{ .seat = existing, .outcome = .unchanged };
            if (!existing.active and !active) return .{ .seat = null, .outcome = .already_inactive };
            if (existing.active and !active) {
                _ = try self.deactivate(external_id);
                return .{ .seat = null, .outcome = .deactivated_seat_burned };
            }
            // Inactive -> active. A NEW seat, deliberately: returning the old
            // index would un-retire a burned one.
            const seat = try self.allocateSeat(external_id, zone, display_name);
            return .{ .seat = seat, .outcome = .reactivated_new_seat };
        }

        if (!active) {
            // Created already-inactive. Nothing to burn, because nothing was
            // ever issued — recording a seat here would hand out an index the
            // IdP has already said should not exist.
            return .{ .seat = null, .outcome = .already_inactive };
        }
        const seat = try self.allocateSeat(external_id, zone, display_name);
        return .{ .seat = seat, .outcome = .created };
    }

    fn allocateSeat(
        self: *Mirror,
        external_id: []const u8,
        zone: Zone,
        display_name: []const u8,
    ) !Seat {
        const index = try self.store.allocateIndex(&zone.cert_id, member_resource, member_flag);
        const node = try identity.deriveChildIdentity(
            self.allocator,
            self.email,
            self.salt,
            zone.derivation_path,
            member_resource,
            member_flag,
            index,
        );
        self.allocator.free(node.invoice_number);
        errdefer self.allocator.free(node.derivation_path);

        try self.store.putNode(.{
            .cert_id = &node.cert_id,
            .parent_cert_id = &zone.cert_id,
            .resource_id = member_resource,
            .domain_flag = member_flag,
            .child_index = index,
            .label = display_name,
        });

        const seat = Seat{
            .external_id = try self.allocator.dupe(u8, external_id),
            .zone_external_id = try self.allocator.dupe(u8, zone.external_id),
            .cert_id = node.cert_id,
            .public_key_hex = node.public_key_hex,
            .derivation_path = node.derivation_path,
            .child_index = index,
            .active = true,
        };
        if (self.seats.fetchRemove(external_id)) |old| old.value.deinit(self.allocator);
        try self.seats.put(seat.external_id, seat);
        // Keyed by the seat's OWN copy of the id, so the map's key outlives the
        // caller's slice.
        return seat;
    }

    /// Burn a seat. Returns the zone's new high-water mark.
    ///
    /// This is where an IdP's advisory flag becomes something a key hierarchy
    /// honours. What it does NOT do is reach a unit already in the field —
    /// spending the departing holder's capability grants is a separate act.
    pub fn deactivate(self: *Mirror, external_id: []const u8) !u64 {
        const entry = self.seats.getEntry(external_id) orelse return Error.UnknownExternalId;
        if (!entry.value_ptr.active) return Error.UnknownExternalId;
        const zone = self.zones.get(entry.value_ptr.zone_external_id) orelse return Error.ZoneNotFound;
        const mark = try self.store.burnSlot(&zone.cert_id, member_resource, member_flag);
        // The record is KEPT and marked inactive rather than dropped. Forgetting
        // it would make a later reactivation indistinguishable from a first
        // create, which is a lie in the audit trail and hides that the person
        // is on their second seat.
        entry.value_ptr.active = false;
        return mark;
    }

    /// The person's CURRENT seat, or null if they have none right now.
    pub fn lookup(self: *Mirror, external_id: []const u8) ?Seat {
        const seat = self.seats.get(external_id) orelse return null;
        return if (seat.active) seat else null;
    }

    /// True when this externalId has been seen before, active or not. Lets a
    /// caller distinguish "deactivated" from "never existed" — the map keeps
    /// burned seats precisely so that question has an answer.
    pub fn known(self: *Mirror, external_id: []const u8) bool {
        return self.seats.contains(external_id);
    }

    pub fn activeSeats(self: *Mirror) usize {
        var n: usize = 0;
        var it = self.seats.valueIterator();
        while (it.next()) |s| {
            if (s.active) n += 1;
        }
        return n;
    }
};
