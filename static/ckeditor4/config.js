/**
 * @license Copyright (c) 2003-2024, CKSource Holding sp. z o.o. All rights reserved.
 * For licensing, see https://ckeditor.com/legal/ckeditor-oss-license
 */

CKEDITOR.editorConfig = function( config ) {
	// Define changes to default configuration here. For example:
	// config.language = 'fr';
	// config.uiColor = '#AADC6E';

	// Disable plugins that cause warnings but we don't use
	config.removePlugins = 'exportpdf,uploadimage';

	// Disable codesnippet if highlight.js is missing
	// config.removePlugins = 'exportpdf,uploadimage,codesnippet';
};
