// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package internal

const (
	bucketQuotaConfigFile = "quota.json"
	bucketTargetsFile     = "bucket-targets.json"
)

//// PutBucketQuotaConfigHandler - PUT Bucket quota configuration.
//// ----------
//// Places a quota configuration on the specified bucket. The quota
//// specified in the quota configuration will be applied by default
//// to enforce total quota for the specified bucket.
//func (a adminAPIHandlers) PutBucketQuotaConfigHandler(w http.ResponseWriter, r *http.Request) {
//	ctx := newContext(r, w, "PutBucketQuotaConfig")
//
//	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))
//
//	objectAPI, _ := validateAdminReq(ctx, w, r, iampolicy.SetBucketQuotaAdminAction)
//	if objectAPI == nil {
//		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
//		return
//	}
//
//	vars := mux.Vars(r)
//	bucket := pathClean(vars["bucket"])
//
//	if _, err := objectAPI.GetBucketInfo(ctx, bucket); err != nil {
//		writeErrorResponseJSON(ctx, w, toAPIError(ctx, err), r.URL)
//		return
//	}
//
//	data, err := ioutil.ReadAll(r.Body)
//	if err != nil {
//		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
//		return
//	}
//
//	if _, err = parseBucketQuota(bucket, data); err != nil {
//		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
//		return
//	}
//
//	//if err = globalBucketMetadataSys.Update(bucket, "", bucketQuotaConfigFile, data); err != nil {
//	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
//	//	return
//	//}
//
//	// Write success response.
//	writeSuccessResponseHeadersOnly(w)
//}
