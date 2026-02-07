import React from 'react';
import { HiShieldCheck, HiFingerPrint, HiCpuChip, HiGlobeAlt, HiLockClosed, HiBolt, HiCommandLine } from 'react-icons/hi2';

// Import Modal-style components
import ModalNavbar from './ModalNavbar';
import ModalHero from './ModalHero';
import ModalFeatureCards from './ModalFeatureCards';
import ModalPricing from './ModalPricing';
import ModalFooter from './ModalFooter';

/**
 * ModalStyleDemo - Demo page showcasing all Modal-style components
 * This is a reference implementation showing how to use the component library
 */
export default function ModalStyleDemo() {
    // Navigation items
    const navItems = [
        { label: 'Products', href: '#products' },
        { label: 'Pricing', href: '#pricing' },
        { label: 'Docs', href: '#docs' },
        { label: 'Blog', href: '#blog' },
    ];

    // Features for the feature cards section
    const features = [
        {
            icon: HiFingerPrint,
            title: 'Wallet Authentication',
            description: 'Passwordless login with Ethereum using SIWE (EIP-4361). No emails, no passwords.',
            accentColor: 'emerald',
        },
        {
            icon: HiCpuChip,
            title: 'AI Risk Engine',
            description: 'Real-time behavioral analysis and anomaly detection powered by machine learning.',
            accentColor: 'teal',
        },
        {
            icon: HiLockClosed,
            title: 'GuardLayer DLP',
            description: 'LLM-powered data leak prevention with regex patterns and smart content filtering.',
            accentColor: 'blue',
        },
        {
            icon: HiGlobeAlt,
            title: 'On-Chain Audit',
            description: 'Merkle-batched Ethereum proofs for transparent, immutable security logs.',
            accentColor: 'purple',
        },
    ];

    // Pricing tiers
    const pricingTiers = [
        {
            name: 'Free',
            price: '$0',
            period: '/month',
            description: 'Perfect for side projects',
            features: [
                'Up to 1,000 auth events',
                'Basic risk scoring',
                'Email support',
                '7-day audit logs',
            ],
            ctaText: 'Get Started',
        },
        {
            name: 'Pro',
            price: '$49',
            period: '/month',
            description: 'For growing applications',
            features: [
                'Up to 100,000 auth events',
                'Advanced AI risk engine',
                'GuardLayer DLP',
                '30-day audit logs',
                'Priority support',
            ],
            ctaText: 'Start Free Trial',
            highlighted: true,
            badge: 'Most Popular',
        },
        {
            name: 'Enterprise',
            price: 'Custom',
            period: '',
            description: 'For large scale deployments',
            features: [
                'Unlimited auth events',
                'Custom risk models',
                'On-chain audit proofs',
                'Unlimited audit retention',
                'Dedicated support',
                'SLA guarantee',
            ],
            ctaText: 'Contact Sales',
        },
    ];

    // Footer columns
    const footerColumns = [
        {
            title: 'Product',
            links: [
                { label: 'Overview', href: '#' },
                { label: 'Features', href: '#' },
                { label: 'Pricing', href: '#' },
                { label: 'Changelog', href: '#' },
            ],
        },
        {
            title: 'Developers',
            links: [
                { label: 'Documentation', href: '#' },
                { label: 'API Reference', href: '#' },
                { label: 'SDKs', href: '#' },
                { label: 'Examples', href: '#' },
            ],
        },
        {
            title: 'Company',
            links: [
                { label: 'About', href: '#' },
                { label: 'Blog', href: '#' },
                { label: 'Careers', href: '#' },
                { label: 'Contact', href: '#' },
            ],
        },
    ];

    return (
        <div className="min-h-screen bg-[#0a0a0f]">
            {/* Navigation */}
            <ModalNavbar
                navItems={navItems}
                ctaButton={{ text: 'Get Started' }}
                onCtaClick={() => console.log('CTA clicked')}
            />

            {/* Hero Section */}
            <ModalHero
                badge={{ text: 'Web3 Security Platform', emoji: '🛡️' }}
                headline="Adaptive security that developers love"
                subheadline="Verify identity, analyze behavior, protect data — and record every decision on-chain. Powered by AI-driven risk analysis."
                onPrimaryClick={() => console.log('Primary CTA clicked')}
                onSecondaryClick={() => console.log('Secondary CTA clicked')}
            />

            {/* Feature Cards */}
            <ModalFeatureCards
                sectionTitle="Build secure applications faster"
                sectionSubtitle="Everything you need to protect your users and data"
                features={features}
                columns={4}
            />

            {/* Pricing */}
            <ModalPricing
                sectionTitle="Simple, transparent pricing"
                sectionSubtitle="Start free and scale as you grow"
                tiers={pricingTiers}
            />

            {/* Footer */}
            <ModalFooter
                columns={footerColumns}
                bottomText="© 2024 SentinelX. All rights reserved."
            />
        </div>
    );
}
