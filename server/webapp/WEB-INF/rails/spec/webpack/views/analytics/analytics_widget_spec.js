/*
 * Copyright 2019 ThoughtWorks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import {TestHelper} from "views/pages/spec/test_helper";

describe("Analytics Widget", () => {
  const m = require('mithril');
  require('jasmine-jquery');

  const AnalyticsWidget = require('views/analytics/analytics_widget');

  const helper = new TestHelper();
  afterEach(helper.unmount.bind(helper));

  beforeEach(() => {
    jasmine.Ajax.install();
    mount();
  });

  afterEach(() => {
    jasmine.Ajax.uninstall();
  });

  it('should render analytics header', () => {
    expect(helper.find('.header-panel')).toBeInDOM();
    expect(helper.find('.header-panel')).toContainText("Analytics");
  });

  it('should render global tab', () => {
    expect(helper.find('.dashboard-tabs li').get(0)).toContainText("Global");
  });

  it('should render pipelines tab', () => {
    expect(helper.find('.dashboard-tabs li').get(1)).toContainText("Pipeline");
  });

  it('should render global chart contents when global tab is selected', () => {
    expect(helper.find('.dashboard-tabs li').get(0)).toContainText("Global");
    expect(helper.find('.dashboard-tabs li').get(0)).toHaveClass("current");
    expect(helper.find('.global')).toBeInDOM();
  });

  it('should render global chart contents when global tab is selected', () => {
    helper.find('.dashboard-tabs li').get(1).click();
    m.redraw();

    expect(helper.find('.dashboard-tabs li').get(1)).toContainText("Pipeline");
    expect(helper.find('.dashboard-tabs li').get(1)).toHaveClass("current");
    expect(helper.find('.pipeline')).toBeInDOM();
  });

  it('should render no analytics plugin installed message when no analytics plugin is installed', () => {
    helper.unmount();
    mount(0);

    expect(helper.find('.info')).toContainText('No analytics plugin installed.');
  });


  const mount = (analyticsPluginCount = 1) => {
    const pluginInfos = function () {
      return {
        countPluginInfo: () => analyticsPluginCount
      };
    };

    helper.mount(() => <AnalyticsWidget metrics={{}} pipelines={[]} pluginInfos={pluginInfos}/>);
  };

});
