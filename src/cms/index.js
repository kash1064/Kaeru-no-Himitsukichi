// @flow strict
import CMS from 'netlify-cms-app';
import PagePreview from './preview-templates/page-preview';
import PostPreview from './preview-templates/post-preview';

CMS.registerPreviewTemplate('Pages', PagePreview);
CMS.registerPreviewTemplate('Posts', PostPreview);
CMS.registerPreviewTemplate('Notes', PostPreview);
