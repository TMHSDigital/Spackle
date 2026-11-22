"use strict";

const SORTABLE = new Set(["created_at", "total", "status"]);

function normalizeSort(sort) {
  return SORTABLE.has(sort) ? sort : "created_at";
}

function buildWhere(filters) {
  const clauses = [];
  if (filters.status) {
    clauses.push("status = '" + filters.status + "'");
  }
  if (filters.customer) {
    clauses.push("customer LIKE '%" + filters.customer + "%'");
  }
  const minTotal = Number(filters.minTotal);
  if (filters.minTotal !== undefined && Number.isFinite(minTotal)) {
    clauses.push("total >= " + minTotal);
  }
  return clauses.length ? "WHERE " + clauses.join(" AND ") : "";
}

module.exports = { normalizeSort, buildWhere };
