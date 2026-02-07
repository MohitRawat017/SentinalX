import React from 'react';
import { useNavigate } from 'react-router-dom';
import { HiShieldCheck, HiFingerPrint, HiCpuChip, HiGlobeAlt, HiLockClosed, HiArrowRight } from 'react-icons/hi2';

// Import Modal-style components
import ModalNavbar from './ModalNavbar';
import ModalFeatureCards from './ModalFeatureCards';
import ModalFooter from './ModalFooter';
import AnimatedBackground from './AnimatedBackground';

/**
 * LandingPage - Main landing page with Three.js animations
 * Features: Animated background, hero section, feature cards, footer
 */
export default function LandingPage() {
    const navigate = useNavigate();

    // Navigation items (simplified)
    const navItems = [
        { label: 'Features', href: '#features' },
        { label: 'Docs', href: 'https://github.com' },
    ];

    // Features for the feature cards section
    const features = [
        {
            icon: HiFingerPrint,
            title: 'SIWE Wallet Authentication',
            description: 'Passwordless login with Ethereum using SIWE (EIP-4361). No emails, no passwords, just your wallet.',
            accentColor: 'emerald',
        },
        {
            icon: HiCpuChip,
            title: 'AI-Powered Risk Engine',
            description: 'Real-time behavioral analysis and anomaly detection powered by advanced machine learning models.',
            accentColor: 'teal',
        },
        {
            icon: HiLockClosed,
            title: 'GuardLayer DLP',
            description: 'LLM-powered data leak prevention with intelligent content filtering and regex pattern matching.',
            accentColor: 'blue',
        },
        {
            icon: HiGlobeAlt,
            title: 'On-Chain Audit Trail',
            description: 'Merkle-batched Ethereum proofs for transparent, immutable, and verifiable security logs.',
            accentColor: 'purple',
        },
    ];

    // Footer columns
    const footerColumns = [
        {
            title: 'Product',
            links: [
                { label: 'Features', href: '#features' },
                { label: 'Security', href: '#' },
                { label: 'Enterprise', href: '#' },
            ],
        },
        {
            title: 'Developers',
            links: [
                { label: 'Documentation', href: '#' },
                { label: 'API Reference', href: '#' },
                { label: 'SDKs', href: '#' },
            ],
        },
        {
            title: 'Company',
            links: [
                { label: 'About', href: '#' },
                { label: 'Contact', href: '#' },
                { label: 'GitHub', href: 'https://github.com' },
            ],
        },
    ];

    const handleGetStarted = () => {
        navigate('/login');
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-white overflow-hidden">
            {/* Navigation */}
            <ModalNavbar
                navItems={navItems}
                ctaButton={{ text: 'Get Started' }}
                onCtaClick={handleGetStarted}
            />

            {/* Hero Section with Three.js Background */}
            <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
                {/* Three.js Animated Background */}
                <AnimatedBackground />

                {/* Gradient overlays for depth */}
                <div className="absolute inset-0 bg-gradient-to-br from-[#0a0a0f]/80 via-transparent to-[#0a0a0f]/90 z-[1]" />
                <div className="absolute bottom-0 left-0 right-0 h-64 bg-gradient-to-t from-[#0a0a0f] to-transparent z-[1]" />

                {/* Animated glow spots */}
                <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-emerald-500/10 rounded-full blur-[150px] animate-pulse z-0" />
                <div className="absolute bottom-1/3 right-1/4 w-[400px] h-[400px] bg-teal-500/10 rounded-full blur-[120px] animate-pulse z-0" style={{ animationDelay: '1s' }} />
                <div className="absolute top-1/2 right-1/3 w-[300px] h-[300px] bg-blue-500/5 rounded-full blur-[100px] animate-pulse z-0" style={{ animationDelay: '2s' }} />

                {/* Content */}
                <div className="relative z-10 max-w-5xl mx-auto px-4 text-center pt-20">
                    {/* Badge */}
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-8 backdrop-blur-sm animate-fade-in-up">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                        <span className="text-sm text-gray-300">Web3 Security Platform</span>
                    </div>

                    {/* Headline with gradient animation */}
                    <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6 animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
                        <span className="bg-gradient-to-r from-white via-emerald-200 to-teal-200 bg-clip-text text-transparent bg-[length:200%_auto] animate-gradient">
                            Adaptive Security
                        </span>
                        <br />
                        <span className="text-gray-400">
                            for the Modern Web
                        </span>
                    </h1>

                    {/* Subheadline */}
                    <p className="text-lg md:text-xl text-gray-400 max-w-2xl mx-auto mb-10 leading-relaxed animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
                        Verify identity, analyze behavior, protect your data — and record every
                        security decision on-chain. Powered by AI-driven risk analysis.
                    </p>

                    {/* CTA Buttons */}
                    <div className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
                        <button
                            onClick={handleGetStarted}
                            className="group flex items-center gap-2 px-8 py-4 rounded-full bg-gradient-to-r from-emerald-500 to-teal-500 text-white font-semibold hover:shadow-xl hover:shadow-emerald-500/25 transition-all duration-300 hover:scale-105"
                        >
                            Get Started
                            <HiArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                        </button>

                        <a
                            href="https://github.com"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-8 py-4 rounded-full border border-white/20 text-white font-medium hover:bg-white/5 transition-all backdrop-blur-sm"
                        >
                            View on GitHub
                        </a>
                    </div>

                    {/* Trust indicators */}
                    <div className="mt-16 flex flex-wrap items-center justify-center gap-8 text-sm text-gray-500 animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
                        <div className="flex items-center gap-2">
                            <HiShieldCheck className="w-4 h-4 text-emerald-500" />
                            <span>SOC 2 Compliant</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <HiGlobeAlt className="w-4 h-4 text-emerald-500" />
                            <span>On-chain Verified</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <HiCpuChip className="w-4 h-4 text-emerald-500" />
                            <span>AI-Powered</span>
                        </div>
                    </div>
                </div>

                {/* Scroll indicator */}
                <div className="absolute bottom-8 left-1/2 -translate-x-1/2 z-10 animate-bounce">
                    <div className="w-6 h-10 rounded-full border-2 border-white/20 flex items-start justify-center p-2">
                        <div className="w-1 h-2 rounded-full bg-white/50 animate-scroll" />
                    </div>
                </div>
            </section>

            {/* Feature Cards */}
            <section id="features">
                <ModalFeatureCards
                    sectionTitle="Built for Security-First Teams"
                    sectionSubtitle="Everything you need to protect your users and data with cutting-edge Web3 security"
                    features={features}
                    columns={4}
                />
            </section>

            {/* Stats Section */}
            <section className="relative py-20 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-b from-[#0a0a0f] via-emerald-950/10 to-[#0a0a0f]" />
                <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
                        {[
                            { value: '99.9%', label: 'Uptime SLA' },
                            { value: '<50ms', label: 'Risk Scoring' },
                            { value: '10K+', label: 'Auth Events/sec' },
                            { value: '100%', label: 'On-chain Proof' },
                        ].map((stat, i) => (
                            <div key={i} className="text-center">
                                <div className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-emerald-400 to-teal-400 bg-clip-text text-transparent mb-2">
                                    {stat.value}
                                </div>
                                <div className="text-sm text-gray-500">{stat.label}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* CTA Section */}
            <section className="relative py-20">
                <div className="absolute inset-0 bg-gradient-to-br from-emerald-950/20 to-transparent" />
                <div className="relative z-10 max-w-3xl mx-auto px-4 text-center">
                    <h2 className="text-3xl md:text-4xl font-bold mb-4">
                        Ready to secure your application?
                    </h2>
                    <p className="text-gray-400 mb-8">
                        Get started in minutes with our SDK. No credit card required.
                    </p>
                    <button
                        onClick={handleGetStarted}
                        className="group inline-flex items-center gap-2 px-8 py-4 rounded-full bg-white text-black font-semibold hover:bg-gray-100 transition-all hover:shadow-xl hover:shadow-white/10"
                    >
                        Start Building
                        <HiArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                    </button>
                </div>
            </section>

            {/* Footer */}
            <ModalFooter
                columns={footerColumns}
                bottomText="© 2024 SentinelX. All rights reserved."
            />
        </div>
    );
}
