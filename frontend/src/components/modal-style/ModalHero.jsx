import React from 'react';
import { HiArrowRight } from 'react-icons/hi2';

/**
 * ModalHero - A striking hero section inspired by Modal.com
 * Features: Large gradient text, animated background, dual CTA buttons
 */
export default function ModalHero({
    badge = { text: 'Web3 Security Platform', emoji: '🛡️' },
    headline = 'AI infrastructure that developers love',
    subheadline = 'Define everything in code, scale from zero to thousands, and keep your security tight.',
    primaryCta = { text: 'Get Started', href: '/signup' },
    secondaryCta = { text: 'Read Docs', href: '/docs' },
    onPrimaryClick,
    onSecondaryClick,
}) {
    return (
        <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
            {/* Animated gradient background */}
            <div className="absolute inset-0 bg-gradient-to-br from-[#0a0a0f] via-[#0d0d15] to-[#12121c]" />

            {/* Subtle grid overlay */}
            <div
                className="absolute inset-0 opacity-20"
                style={{
                    backgroundImage: `radial-gradient(circle at 1px 1px, rgba(255,255,255,0.05) 1px, transparent 0)`,
                    backgroundSize: '40px 40px',
                }}
            />

            {/* Glow effects */}
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/20 rounded-full blur-[128px]" />
            <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-teal-500/10 rounded-full blur-[128px]" />

            {/* Content */}
            <div className="relative z-10 max-w-5xl mx-auto px-4 text-center pt-20">
                {/* Badge */}
                {badge && (
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-8">
                        {badge.emoji && <span>{badge.emoji}</span>}
                        <span className="text-sm text-gray-300">{badge.text}</span>
                    </div>
                )}

                {/* Headline */}
                <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
                    <span className="bg-gradient-to-r from-white via-gray-200 to-gray-400 bg-clip-text text-transparent">
                        {headline}
                    </span>
                </h1>

                {/* Subheadline */}
                <p className="text-lg md:text-xl text-gray-400 max-w-2xl mx-auto mb-10 leading-relaxed">
                    {subheadline}
                </p>

                {/* CTA Buttons */}
                <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                    <button
                        onClick={onPrimaryClick}
                        className="group flex items-center gap-2 px-8 py-4 rounded-full bg-white text-black font-semibold hover:bg-gray-100 transition-all hover:shadow-xl hover:shadow-white/10"
                    >
                        {primaryCta.text}
                        <HiArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                    </button>

                    <button
                        onClick={onSecondaryClick}
                        className="px-8 py-4 rounded-full border border-white/20 text-white font-medium hover:bg-white/5 transition-all"
                    >
                        {secondaryCta.text}
                    </button>
                </div>

                {/* Optional stats or trust badges */}
                <div className="mt-16 flex flex-wrap items-center justify-center gap-8 text-sm text-gray-500">
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500" />
                        <span>SOC 2 Compliant</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500" />
                        <span>On-chain Verified</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500" />
                        <span>AI-Powered Security</span>
                    </div>
                </div>
            </div>
        </section>
    );
}
