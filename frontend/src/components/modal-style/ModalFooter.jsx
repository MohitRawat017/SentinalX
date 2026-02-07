import React from 'react';
import { HiShieldCheck } from 'react-icons/hi2';

/**
 * ModalFooter - Minimal footer inspired by Modal.com
 * Features: Multi-column layout, social links, dark theme
 */
export default function ModalFooter({
    logo = { icon: HiShieldCheck, text: 'SentinelX' },
    columns = [],
    bottomText = '© 2024 SentinelX. All rights reserved.',
    socialLinks = [],
}) {
    return (
        <footer className="relative border-t border-white/5">
            {/* Background */}
            <div className="absolute inset-0 bg-[#0a0a0f]" />

            <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Main Footer Content */}
                <div className="py-12 md:py-16 grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-8">
                    {/* Logo Column */}
                    <div className="col-span-2 md:col-span-1 lg:col-span-1">
                        <a href="/" className="flex items-center gap-2 mb-4">
                            <div className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-teal-400 rounded-lg flex items-center justify-center">
                                <logo.icon className="w-5 h-5 text-white" />
                            </div>
                            <span className="text-lg font-bold text-white">
                                {logo.text}
                            </span>
                        </a>
                        <p className="text-sm text-gray-500 leading-relaxed">
                            Adaptive security for the modern web.
                        </p>

                        {/* Social Links */}
                        {socialLinks.length > 0 && (
                            <div className="flex items-center gap-4 mt-6">
                                {socialLinks.map((social, index) => (
                                    <a
                                        key={index}
                                        href={social.href}
                                        className="text-gray-500 hover:text-white transition-colors"
                                        aria-label={social.label}
                                    >
                                        <social.icon className="w-5 h-5" />
                                    </a>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Link Columns */}
                    {columns.map((column, index) => (
                        <div key={index}>
                            <h4 className="text-sm font-semibold text-white mb-4">{column.title}</h4>
                            <ul className="space-y-3">
                                {column.links.map((link, linkIndex) => (
                                    <li key={linkIndex}>
                                        <a
                                            href={link.href}
                                            className="text-sm text-gray-500 hover:text-white transition-colors"
                                        >
                                            {link.label}
                                        </a>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </div>

                {/* Bottom Bar */}
                <div className="py-6 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between gap-4">
                    <p className="text-sm text-gray-500">{bottomText}</p>

                    <div className="flex items-center gap-6 text-sm text-gray-500">
                        <a href="/privacy" className="hover:text-white transition-colors">Privacy</a>
                        <a href="/terms" className="hover:text-white transition-colors">Terms</a>
                        <a href="/security" className="hover:text-white transition-colors">Security</a>
                    </div>
                </div>
            </div>
        </footer>
    );
}
