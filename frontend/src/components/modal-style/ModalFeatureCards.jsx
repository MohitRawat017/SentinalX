import React from 'react';
import { HiArrowRight } from 'react-icons/hi2';

/**
 * ModalFeatureCards - Feature grid inspired by Modal.com
 * Features: Glassmorphism cards, hover animations, icon support
 */
export default function ModalFeatureCards({
    sectionTitle = 'Designed to help teams deploy faster',
    sectionSubtitle = 'Everything you need to build secure, scalable applications',
    features = [],
    columns = 4, // 2, 3, or 4
}) {
    const gridCols = {
        2: 'md:grid-cols-2',
        3: 'md:grid-cols-3',
        4: 'md:grid-cols-2 lg:grid-cols-4',
    };

    return (
        <section className="relative py-20 md:py-32">
            {/* Background */}
            <div className="absolute inset-0 bg-gradient-to-b from-[#0a0a0f] to-[#0d0d15]" />

            <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Section Header */}
                <div className="text-center mb-16">
                    <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight mb-4">
                        <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                            {sectionTitle}
                        </span>
                    </h2>
                    {sectionSubtitle && (
                        <p className="text-lg text-gray-400 max-w-2xl mx-auto">
                            {sectionSubtitle}
                        </p>
                    )}
                </div>

                {/* Feature Cards Grid */}
                <div className={`grid grid-cols-1 ${gridCols[columns]} gap-6`}>
                    {features.map((feature, index) => (
                        <FeatureCard key={index} {...feature} />
                    ))}
                </div>
            </div>
        </section>
    );
}

function FeatureCard({
    icon: Icon,
    title,
    description,
    href,
    accentColor = 'emerald', // emerald, teal, blue, purple
}) {
    const accentColors = {
        emerald: 'group-hover:text-emerald-400 group-hover:shadow-emerald-500/20',
        teal: 'group-hover:text-teal-400 group-hover:shadow-teal-500/20',
        blue: 'group-hover:text-blue-400 group-hover:shadow-blue-500/20',
        purple: 'group-hover:text-purple-400 group-hover:shadow-purple-500/20',
    };

    const iconBgColors = {
        emerald: 'bg-emerald-500/10 group-hover:bg-emerald-500/20',
        teal: 'bg-teal-500/10 group-hover:bg-teal-500/20',
        blue: 'bg-blue-500/10 group-hover:bg-blue-500/20',
        purple: 'bg-purple-500/10 group-hover:bg-purple-500/20',
    };

    const CardWrapper = href ? 'a' : 'div';

    return (
        <CardWrapper
            href={href}
            className={`group relative p-6 rounded-2xl bg-white/[0.02] backdrop-blur-sm border border-white/5 hover:border-white/10 transition-all duration-300 hover:bg-white/[0.04] ${accentColors[accentColor]}`}
        >
            {/* Icon */}
            {Icon && (
                <div className={`w-12 h-12 rounded-xl ${iconBgColors[accentColor]} flex items-center justify-center mb-4 transition-all`}>
                    <Icon className={`w-6 h-6 text-gray-400 ${accentColors[accentColor].split(' ')[0]}`} />
                </div>
            )}

            {/* Title */}
            <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-white transition-colors">
                {title}
            </h3>

            {/* Description */}
            <p className="text-sm text-gray-500 leading-relaxed">
                {description}
            </p>

            {/* Link indicator */}
            {href && (
                <div className="mt-4 flex items-center gap-1 text-sm text-gray-500 group-hover:text-white transition-colors">
                    <span>Learn more</span>
                    <HiArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                </div>
            )}
        </CardWrapper>
    );
}

// Export individual card for standalone use
export { FeatureCard };
