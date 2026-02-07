import React from 'react';
import { HiShieldCheck } from 'react-icons/hi2';

/**
 * ModalNavbar - A sleek, minimal navigation bar inspired by Modal.com
 * Features: Dark background, glassmorphism, centered logo, CTA button
 */
export default function ModalNavbar({
    logo = { icon: HiShieldCheck, text: 'SentinelX' },
    navItems = [],
    ctaButton = { text: 'Get Started', href: '/signup' },
    onCtaClick,
}) {
    return (
        <nav className="fixed top-0 left-0 right-0 z-50 bg-black/50 backdrop-blur-xl border-b border-white/5">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-16">
                    {/* Logo */}
                    <a href="/" className="flex items-center gap-2 group">
                        <div className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-teal-400 rounded-lg flex items-center justify-center group-hover:shadow-lg group-hover:shadow-emerald-500/25 transition-all">
                            <logo.icon className="w-5 h-5 text-white" />
                        </div>
                        <span className="text-lg font-bold text-white">
                            {logo.text}
                        </span>
                    </a>

                    {/* Navigation Items */}
                    <div className="hidden md:flex items-center gap-8">
                        {navItems.map((item) => (
                            <a
                                key={item.label}
                                href={item.href}
                                className="text-sm text-gray-400 hover:text-white transition-colors"
                            >
                                {item.label}
                            </a>
                        ))}
                    </div>

                    {/* CTA Button */}
                    <div className="flex items-center gap-4">
                        <button
                            onClick={onCtaClick}
                            className="px-5 py-2 rounded-full bg-white text-black text-sm font-semibold hover:bg-gray-100 transition-all"
                        >
                            {ctaButton.text}
                        </button>
                    </div>
                </div>
            </div>
        </nav>
    );
}
