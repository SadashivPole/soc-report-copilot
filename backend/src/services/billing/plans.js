'use strict';
/**
 * Billing-ready plan catalog. NO live billing is wired up — this module defines
 * the plans, their entitlements/limits, and a guard used to enforce them. A
 * payment provider (e.g. Stripe) can later populate `tenants.plan` /
 * `subscriptions` without changing enforcement call sites.
 */
const PLANS = {
  free: {
    id: 'free',
    name: 'Free',
    price_monthly: 0,
    blurb: 'Kick the tires on a single workstation.',
    limits: {
      maxTeamMembers: 1,
      maxSchedules: 0,
      maxUploadsPerMonth: 5,
      retentionDays: 30,
      sharing: false,
      branding: false,
      multiClient: false,
      aiProse: false,
    },
    features: [
      '1 seat',
      'Wazuh JSON/CSV upload',
      'Evidence-based dashboard',
      'On-demand PDF report',
      '30-day retention',
    ],
  },
  pro: {
    id: 'pro',
    name: 'Pro',
    price_monthly: 99,
    blurb: 'For a small in-house SOC producing weekly client-ready reports.',
    limits: {
      maxTeamMembers: 5,
      maxSchedules: 5,
      maxUploadsPerMonth: 100,
      retentionDays: 180,
      sharing: true,
      branding: true,
      multiClient: false,
      aiProse: true,
    },
    features: [
      'Up to 5 seats (Admin/Analyst/Viewer)',
      'Weekly scheduled reports by email',
      'Company branding & logo',
      'Secure expiring share links',
      'Optional evidence-bound AI prose',
      '180-day retention',
    ],
  },
  mssp: {
    id: 'mssp',
    name: 'MSSP',
    price_monthly: 399,
    blurb: 'For managed providers delivering reports across many clients.',
    limits: {
      maxTeamMembers: 50,
      maxSchedules: 100,
      maxUploadsPerMonth: 100000,
      retentionDays: 730,
      sharing: true,
      branding: true,
      multiClient: true,
      aiProse: true,
    },
    features: [
      'Up to 50 seats',
      'Unlimited scheduled reports',
      'Per-client branding & naming',
      'Priority support',
      '2-year retention',
      'Everything in Pro',
    ],
  },
};

function getPlan(planId) {
  return PLANS[planId] || PLANS.free;
}

function listPlans() {
  return Object.values(PLANS).map((p) => ({
    id: p.id,
    name: p.name,
    price_monthly: p.price_monthly,
    blurb: p.blurb,
    features: p.features,
    limits: p.limits,
  }));
}

/** Throw an httpError-shaped error when a plan does not include an entitlement. */
function assertEntitled(planId, key) {
  const plan = getPlan(planId);
  if (!plan.limits[key]) {
    const e = new Error(
      `Your ${plan.name} plan does not include this feature. Upgrade to enable it.`
    );
    e.status = 402; // Payment Required — signals an upgrade path
    throw e;
  }
}

module.exports = { PLANS, getPlan, listPlans, assertEntitled };
