<template>
  <div style="position:relative;width:100%;height:100%;flex-direction:column;display:flex">
    <!--<rotate-buttom :hasIcon="true" iconClass="el-icon-arrow-down el-icon--right">旋转吧箭头</rotate-buttom>-->
    <el-header></el-header>
    <div
      style="position:absolute;margin:0 auto;margin-top:48px;width:46%;height:192px;align-self:center;"
    >
      <div>
        <el-card>
          <el-divider content-position="left">角色信息</el-divider>
          <el-table :data="profileData" style="width: 100%" :stripe="true" :border="true">
            <el-table-column width="58">
              <template slot-scope="scope">
                <img
                  style="image-rendering: pixelated;height:38px;width:38px;"
                  v-if="Boolean(scope.row.textures.skin)"
                  :src="getheadurl(scope.row.textures.skin.textureid)"
                >
              </template>
            </el-table-column>
            <el-table-column prop="name" label="角色名称" width="180">
              <template slot-scope="scope">
                <span>{{ scope.row.name }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作">
              <template slot-scope="scope">
                
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </div>
    </div>
  </div>
</template>
<style>
.bea-font {
  font-family: "Helvetica Neue", Helvetica, "PingFang SC", "Hiragino Sans GB",
    "Microsoft YaHei", "微软雅黑", Arial, sans-serif;
}
</style>
<script>
import axios from "axios";
import config from "../../config.js";

export default {
  data() {
    return {
      profileData: []
    };
  },
  methods: {
    getheadurl(textureid) {
      return `${config.source}/texture/textureid/${textureid}/head`;
    }
  },
  mounted() {
    let that = this;
    axios
      .get(
        `${
          config.source
        }/api/knowledgefruits/search/profiles/createby/62ded08c5cac4993a5fa8bc3d3425376`
      )
      .then(function(response) {
        that.profileData = response.data;
        console.log(that.profileData);
      });
  }
};
</script>