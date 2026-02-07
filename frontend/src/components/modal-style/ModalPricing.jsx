import React from 'react';
import { HiCheck } from 'react-icons/hi2';

/**
 * ModalPricing - Pricing section inspired by Modal.com
 * Features: Glassmorphism cards, highlighted tier, feature lists
 */
export default function ModalPricing({
    sectionTitle = 'Simple, transparent pricing',
    sectionSubtitle = 'Start free, scale as you grow',
    tiers = [],
}) {
    return (
        <section className="relative py-20 md:py-32">
            {/* Background */}
            <div className="absolute inset-0 bg-gradient-to-br from-[#0d0d15] via-[#0a0a0f] to-[#12121c]" />

            {/* Subtle glow */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-emerald-500/5 rounded-full blur-[128px]" />

            <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Section Header */}
                <div className="text-center mb-16">
                    <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight mb-4">
                        <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                            {sectionTitle}
                        </span>
                    </h2>
                    {sectionSubtitle && (
                        <p className="text-lg text-gray-400">
                            {sectionSubtitle}
                        </p>
                    )}
                </div>

                {/* Pricing Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto">
                    {tiers.map((tier, index) => (
                        <PricingCard key={index} {...tier} />
                    ))}
                </div>
            </div>
        </section>
    );
}

function PricingCard({
    name,
    price,
    period = '/month',
    description,
    features = [],
    ctaText = 'Get Started',
    ctaHref,
    onCtaClick,
    highlighted = false,
    badge,
}) {
    return (
        <div
            className={`relative p-8 rounded-2xl transition-all duration-300 ${highlighted
                    ? 'bg-gradient-to-b from-emerald-500/10 to-transparent border-2 border-emerald-500/30 scale-105'
                    : 'bg-white/[0.02] border border-white/5 hover:border-white/10'
                }`}
        >
            {/* Badge */}
            {badge && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <span className="px-3 py-1 rounded-full text-xs font-semibold bg-gradient-to-r from-emerald-500 to-teal-400 text-white">
                        {badge}
                    </span>
                </div>
            )}

            {/* Tier Name */}
            <h3 className="text-xl font-semibold text-white mb-2">{name}</h3>

            {/* Description */}
            {description && (
                <p className="text-sm text-gray-500 mb-6">{description}</p>
            )}

            {/* Price */}
            <div className="mb-6">
                <span className="text-4xl font-bold text-white">{price}</span>
                {period && <span className="text-gray-500 ml-1">{period}</span>}
            </div>

            {/* CTA Button */}
            <button
                onClick={onCtaClick}
                className={`w-full py-3 rounded-xl font-semibold transition-all ${highlighted
                        ? 'bg-gradient-to-r from-emerald-500 to-teal-400 text-white hover:opacity-90'
                        : 'bg-white/5 text-white border border-white/10 hover:bg-white/10'
                    }`}
            >
                {ctaText}
            </button>

            {/* Features List */}
            {features.length > 0 && (
                <ul className="mt-8 space-y-3">
                    {features.map((feature, index) => (
                        <li key={index} className="flex items-start gap-3">
                            <HiCheck className={`w-5 h-5 flex-shrink-0 mt-0.5 ${highlighted ? 'text-emerald-400' : 'text-gray-500'}`} />
                            <span className="text-sm text-gray-400">{feature}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}

// Export individual card for standalone use
export { PricingCard };
