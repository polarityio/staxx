polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    enrichedDetails: Ember.computed('details', function () {
        let details = this.get('details');

        if (details.severity === 'medium' || details.severity === 'high' || details.severity === 'very-high') {
            details.severityColor = '#FF4559';
        } else {
            details.severityColor = '#FF8F00';
        }

        if (details.confidence > 75) {
            details.confidenceColor = '#388E3C';
        } else {
            details.confidenceColor = '';
        }

        details.tlpDisplay = details.tlp.substring(4);

        return details;
    })
});
