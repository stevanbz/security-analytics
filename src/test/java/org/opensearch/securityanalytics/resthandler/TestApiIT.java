package org.opensearch.securityanalytics.resthandler;

import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.aggregation.bucketselectorext.BucketSelectorExtAggregationBuilder;
import org.opensearch.commons.alerting.model.BucketLevelTrigger;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.commons.alerting.model.SearchInput;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;

public class TestApiIT extends SecurityAnalyticsRestTestCase {

    public void testStevan() throws IOException, SigmaError {
        /**XContentParser xcp = XContentFactory.xContent(XContentType.JSON)
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE,  rule);

        Rule rule1 = Rule.docParse(xcp, "1", 1L);

        // Creating bucket level monitor per each aggregation rule
        // TODO - check if bucket level monitors needs to be created per rule
        if(rule1.getAggregationQueries() != null){
            // Create aggregation queries
            XContentParser aggregationQueriesParser = XContentFactory.xContent(XContentType.JSON)
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE,  rule1.getAggregationQueries().get(0).getValue());

            AggregationQueries aggregationQueries = AggregationQueries.docParse(aggregationQueriesParser);
            // Building query query_string based on the aggregation
            QueryBuilder queryBuilder =
                QueryBuilders.queryStringQuery(rule1.getQueries().get(0).getValue());

            QueryBackend queryBackend = new OSQueryBackend(rule1.getCategory(), true, true);

            AggregationBuilder aggregationBuilder = queryBackend.buildAggregation(rule1.getAggregationItemsFromRule().get(0));

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .seqNoAndPrimaryTerm(true)
                .version(true)
                .query(queryBuilder)
                .aggregation(aggregationBuilder)
                .size(10000);

            List<SearchInput> bucketLevelMonitorInputs = new ArrayList<>();
            bucketLevelMonitorInputs.add(new SearchInput(Arrays.asList("windows"), searchSourceBuilder));

            // Bucket level monitor will always have one aggregation and therefore one bucket condition
                    /*
                    XContentParser bucketConditionParser = XContentFactory.xContent(XContentType.JSON)
                        .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE,  aggregationQueries.getBucketTriggerQuery());
                    XContentParserUtils.ensureExpectedToken(Token.START_OBJECT, bucketConditionParser.nextToken(), bucketConditionParser);
                    BucketSelectorExtAggregationBuilder bucketSelectorBuilder = BucketSelectorExtAggregationBuilder.Companion.parse("condition", bucketConditionParser);

            BucketSelectorExtAggregationBuilder bucketSelectorBuilder = queryBackend.buildTriggerCondition(rule1.getAggregationItemsFromRule().get(0));

            DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                Collections.emptyList());
            Detector detector = randomDetectorWithInputs(List.of(input));

            List<DetectorTrigger> detectorTriggers = detector.getTriggers();
            List<BucketLevelTrigger> triggers = new ArrayList<>();

            for (DetectorTrigger detectorTrigger: detectorTriggers) {
                String id = detectorTrigger.getId();
                String name = detectorTrigger.getName();
                String severity = detectorTrigger.getSeverity();
                List<Action> actions = detectorTrigger.getActions();
                BucketLevelTrigger bucketLevelTrigger = new BucketLevelTrigger(id, name, severity, bucketSelectorBuilder, actions);
                triggers.add(bucketLevelTrigger);
            }

            Monitor monitor = new Monitor(Monitor.NO_ID, Monitor.NO_VERSION, detector.getName(), detector.getEnabled(), detector.getSchedule(), detector.getLastUpdateTime(), detector.getEnabledTime(),
                MonitorType.BUCKET_LEVEL_MONITOR, detector.getUser(), 1, bucketLevelMonitorInputs, triggers, Map.of(), new DataSources());

            XContentBuilder builder = monitor.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS);
            String monitorAsString = BytesReference.bytes(builder).utf8ToString();

            IndexMonitorRequest indexMonitorRequest = new IndexMonitorRequest(Monitor.NO_ID, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, RestRequest.Method.POST, monitor);

            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client(), indexMonitorRequest, listener);   */
    }

}
